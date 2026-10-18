//! Process-wide console output without disk/logcat waits on network tasks.
//! All records share one FIFO; no traffic or severity receives preference.

use std::{
    io::{self, Write},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, SyncSender, TrySendError},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

const RECORDS: usize = 512;
const BYTES: u64 = 1024 * 1024;
const MAX_RECORD_BYTES: usize = 64 * 1024;
const WRITE_BATCH_RECORDS: usize = 64;
const WRITE_BATCH_BYTES: usize = 64 * 1024;

/// Local diagnostic counters. Queued bytes include a writer blocked in I/O.
#[derive(Clone, Copy, Debug, Default)]
pub struct ConsoleLogStats {
    pub queued_bytes: u64,
    pub dropped_records: u64,
    pub dropped_bytes: u64,
    pub write_errors: u64,
}

#[derive(Default)]
struct Counters {
    bytes: AtomicU64,
    drops: AtomicU64,
    dropped_bytes: AtomicU64,
    errors: AtomicU64,
}

impl Counters {
    fn snapshot(&self) -> ConsoleLogStats {
        ConsoleLogStats {
            queued_bytes: self.bytes.load(Ordering::Relaxed),
            dropped_records: self.drops.load(Ordering::Relaxed),
            dropped_bytes: self.dropped_bytes.load(Ordering::Relaxed),
            write_errors: self.errors.load(Ordering::Relaxed),
        }
    }

    fn reject(&self, bytes: u64) {
        self.drops.fetch_add(1, Ordering::Relaxed);
        self.dropped_bytes.fetch_add(bytes, Ordering::Relaxed);
    }
}

struct Record {
    bytes: Box<[u8]>,
    counters: Arc<Counters>,
}

impl Drop for Record {
    fn drop(&mut self) {
        self.counters
            .bytes
            .fetch_sub(self.bytes.len() as u64, Ordering::Relaxed);
    }
}

enum Command {
    Record(Record),
    Flush(mpsc::Sender<bool>),
}

struct ConsoleQueue {
    sender: SyncSender<Command>,
    counters: Arc<Counters>,
    byte_limit: u64,
    record_limit: usize,
}

impl ConsoleQueue {
    fn start(
        mut sink: Box<dyn Write + Send>,
        records: usize,
        byte_limit: u64,
        record_limit: usize,
    ) -> io::Result<(Self, JoinHandle<()>)> {
        let (sender, receiver) = mpsc::sync_channel(records);
        let counters = Arc::new(Counters::default());
        let writer_counters = counters.clone();
        let worker = std::thread::Builder::new()
            .name("veil-console-log".into())
            .spawn(move || {
                let mut reported_drops = 0;
                let mut failed = false;
                let mut pending = None;
                let mut records = Vec::with_capacity(WRITE_BATCH_RECORDS);
                let mut output = Vec::with_capacity(WRITE_BATCH_BYTES);
                loop {
                    let command = match pending.take().or_else(|| receiver.recv().ok()) {
                        Some(command) => command,
                        None => break,
                    };
                    let snapshot = writer_counters.snapshot();
                    if snapshot.dropped_records > reported_drops {
                        // Keep the overload notice a complete JSON record even
                        // when a caller configured structured console output.
                        let mut notice = crate::format_log_json(
                            "WARN",
                            "observability.console_dropped",
                            &format!(
                                "records={} bytes={}",
                                snapshot.dropped_records, snapshot.dropped_bytes
                            ),
                        );
                        notice.push('\n');
                        if sink.write_all(notice.as_bytes()).is_err() {
                            writer_counters.errors.fetch_add(1, Ordering::Relaxed);
                            failed = true;
                        }
                        reported_drops = snapshot.dropped_records;
                    }
                    match command {
                        Command::Record(record) => {
                            let mut bytes = record.bytes.len();
                            records.push(record);
                            // Drain only records already ready. There is no
                            // collection timer and Flush remains a FIFO fence.
                            while records.len() < WRITE_BATCH_RECORDS && bytes < WRITE_BATCH_BYTES {
                                match receiver.try_recv() {
                                    Ok(Command::Record(next))
                                        if next.bytes.len() <= WRITE_BATCH_BYTES - bytes =>
                                    {
                                        bytes += next.bytes.len();
                                        records.push(next);
                                    }
                                    Ok(next) => {
                                        pending = Some(next);
                                        break;
                                    }
                                    Err(_) => break,
                                }
                            }
                            output.clear();
                            // A custom queue may allow a record above the
                            // batch bound. Write that record directly instead
                            // of growing the worker's fixed scratch buffer.
                            let data = if records.len() == 1 {
                                &records[0].bytes[..]
                            } else {
                                for record in &records {
                                    output.extend_from_slice(&record.bytes);
                                }
                                &output[..]
                            };
                            if sink.write_all(data).is_err() {
                                writer_counters.errors.fetch_add(1, Ordering::Relaxed);
                                failed = true;
                            }
                            // Keep every byte lease until the whole write
                            // completes, including partial/blocked sink writes.
                            records.clear();
                        }
                        Command::Flush(reply) => {
                            if sink.flush().is_err() {
                                writer_counters.errors.fetch_add(1, Ordering::Relaxed);
                                failed = true;
                            }
                            let _ = reply.send(!failed);
                        }
                    }
                }
                if sink.flush().is_err() {
                    writer_counters.errors.fetch_add(1, Ordering::Relaxed);
                }
            })?;
        Ok((
            Self {
                sender,
                counters,
                byte_limit,
                record_limit,
            },
            worker,
        ))
    }

    fn enqueue(&self, mut line: String) -> bool {
        if !line.ends_with('\n') {
            line.push('\n');
        }
        let len = line.len() as u64;
        if line.len() > self.record_limit
            || self
                .counters
                .bytes
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                    used.checked_add(len)
                        .filter(|next| *next <= self.byte_limit)
                })
                .is_err()
        {
            self.counters.reject(len);
            return false;
        }
        let record = Record {
            // Do not retain an oversized String capacity behind a small line:
            // the byte lease must bound storage, not just visible characters.
            bytes: line.into_bytes().into_boxed_slice(),
            counters: self.counters.clone(),
        };
        if self.sender.try_send(Command::Record(record)).is_err() {
            self.counters.reject(len);
            return false;
        }
        true
    }

    /// An explicit shutdown/diagnostic barrier, never called by enqueue.
    fn flush(&self, timeout: Duration) -> bool {
        let start = Instant::now();
        let (reply, result) = mpsc::channel();
        let mut command = Command::Flush(reply);
        loop {
            match self.sender.try_send(command) {
                Ok(()) => break,
                Err(TrySendError::Disconnected(_)) => return false,
                Err(TrySendError::Full(returned)) => {
                    command = returned;
                    if start.elapsed() >= timeout {
                        return false;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
        result
            .recv_timeout(timeout.saturating_sub(start.elapsed()))
            .unwrap_or(false)
    }
}

static CONSOLE: OnceLock<Result<ConsoleQueue, String>> = OnceLock::new();

fn queue() -> Result<&'static ConsoleQueue, &'static str> {
    CONSOLE
        .get_or_init(|| {
            ConsoleQueue::start(
                super::default_console_sink(),
                RECORDS,
                BYTES,
                MAX_RECORD_BYTES,
            )
            // The process-wide queue lives until process exit. The worker
            // owns no node/runtime/queue sender; ordinary local queues exit
            // when their final producer drops. Explicit flush is bounded.
            .map(|(queue, _worker)| queue)
            .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(String::as_str)
}

pub(super) fn ensure_console_logger() -> io::Result<()> {
    queue().map(|_| ()).map_err(io::Error::other)
}

/// Submit a complete local console record without waiting for its output sink.
/// False means queue/full-size rejection or writer initialization failure.
pub fn enqueue_console_record(line: String) -> bool {
    queue().is_ok_and(|queue| queue.enqueue(line))
}

/// A bounded barrier for shutdown/diagnostic consumers, not a media-path call.
/// True means prior accepted records were flushed, not that none were rejected.
pub fn flush_console_logs(timeout: Duration) -> bool {
    match CONSOLE.get() {
        None => true,
        Some(Ok(queue)) => queue.flush(timeout),
        Some(Err(_)) => false,
    }
}

pub fn console_log_stats() -> ConsoleLogStats {
    match CONSOLE.get() {
        None => ConsoleLogStats::default(),
        Some(Ok(queue)) => queue.counters.snapshot(),
        Some(Err(_)) => ConsoleLogStats {
            write_errors: 1,
            ..ConsoleLogStats::default()
        },
    }
}

#[cfg(test)]
#[path = "console_tests.rs"]
mod tests;
