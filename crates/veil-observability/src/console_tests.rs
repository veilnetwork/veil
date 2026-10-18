use super::*;
use std::sync::Mutex;

struct Sink {
    output: Arc<Mutex<Vec<u8>>>,
    block: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
}

impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Some((entered, release)) = self.block.take() {
            entered.send(()).unwrap();
            release.recv().unwrap();
        }
        self.output.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn blocked_sink_never_blocks_producers_and_records_rejections() {
    let output = Arc::new(Mutex::new(Vec::new()));
    let (entered, blocked) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    let (queue, worker) = ConsoleQueue::start(
        Box::new(Sink {
            output: output.clone(),
            block: Some((entered, resume)),
        }),
        2,
        32,
        16,
    )
    .unwrap();
    let queue = Arc::new(queue);
    assert!(queue.enqueue("first\n".into()));
    blocked.recv_timeout(Duration::from_secs(2)).unwrap();
    let producer_queue = queue.clone();
    let (done, completed) = mpsc::channel();
    let producer = std::thread::spawn(move || {
        let accepted = [
            producer_queue.enqueue("second\n".into()),
            producer_queue.enqueue("third\n".into()),
            producer_queue.enqueue("fourth\n".into()),
            producer_queue.enqueue("oversized record!\n".into()),
        ];
        done.send((accepted, producer_queue.counters.snapshot()))
            .unwrap();
    });
    let result = completed.recv_timeout(Duration::from_millis(500));
    // Always unblock and join the worker even if the progress assertion fails.
    release.send(()).unwrap();
    producer.join().unwrap();
    assert!(queue.flush(Duration::from_secs(2)));
    let (accepted, stats) = result.expect("producer must finish before sink unblocks");
    assert_eq!(accepted, [true, true, false, false]);
    assert_eq!(
        stats.queued_bytes, 19,
        "in-flight first record retains credit"
    );
    assert_eq!(stats.dropped_records, 2);
    assert_eq!(queue.counters.snapshot().queued_bytes, 0);
    drop(queue);
    worker.join().unwrap();
    let bytes = output.lock().unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(text.contains("observability.console_dropped"));
    let first = text.find("first\n").expect("first record");
    let second = text.find("second\n").expect("second record");
    let third = text.find("third\n").expect("third record");
    assert!(first < second && second < third);
    assert!(!text.contains("fourth\n"));
}

#[test]
fn byte_budget_includes_inflight_output_and_flush_timeout_is_bounded() {
    let (entered, blocked) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    let (queue, worker) = ConsoleQueue::start(
        Box::new(Sink {
            output: Arc::default(),
            block: Some((entered, resume)),
        }),
        8,
        12,
        16,
    )
    .unwrap();
    assert!(queue.enqueue("1234567\n".into()));
    blocked.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(queue.enqueue("abc\n".into()));
    assert!(!queue.enqueue("x\n".into()));
    let stats = queue.counters.snapshot();
    let flushed_while_blocked = queue.flush(Duration::from_millis(10));
    release.send(()).unwrap();
    assert!(!flushed_while_blocked);
    assert_eq!(stats.queued_bytes, 12);
    assert_eq!(stats.dropped_records, 1);
    assert!(queue.flush(Duration::from_secs(2)));
    drop(queue);
    worker.join().unwrap();
}

#[test]
fn concurrent_producers_preserve_complete_records_and_each_producers_order() {
    let output = Arc::new(Mutex::new(Vec::new()));
    let (queue, worker) = ConsoleQueue::start(
        Box::new(Sink {
            output: output.clone(),
            block: None,
        }),
        RECORDS,
        BYTES,
        MAX_RECORD_BYTES,
    )
    .unwrap();
    let queue = Arc::new(queue);
    let producers: Vec<_> = (0..4)
        .map(|p| {
            let queue = queue.clone();
            std::thread::spawn(move || {
                for n in 0..100 {
                    assert!(queue.enqueue(format!("{p}:{n}\n")));
                }
            })
        })
        .collect();
    for producer in producers {
        producer.join().unwrap();
    }
    assert!(queue.flush(Duration::from_secs(2)));
    assert_eq!(queue.counters.snapshot().dropped_records, 0);
    assert_eq!(queue.counters.snapshot().queued_bytes, 0);
    drop(queue);
    worker.join().unwrap();
    let bytes = output.lock().unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert_eq!(text.lines().count(), 400);
    for p in 0..4 {
        let actual: Vec<_> = text
            .lines()
            .filter(|line| line.starts_with(&format!("{p}:")))
            .collect();
        let expected: Vec<_> = (0..100).map(|n| format!("{p}:{n}")).collect();
        assert_eq!(actual, expected);
    }
}

#[test]
fn sink_errors_are_visible_and_do_not_panic_or_retain_credit() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("injected sink failure"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let (queue, worker) = ConsoleQueue::start(Box::new(Broken), 2, 32, 16).unwrap();
    assert!(queue.enqueue("one\n".into()));
    assert!(!queue.flush(Duration::from_secs(2)));
    assert_eq!(queue.counters.snapshot().write_errors, 1);
    assert_eq!(queue.counters.snapshot().queued_bytes, 0);
    drop(queue);
    worker.join().unwrap();
}

#[test]
fn ready_records_share_bounded_writes_without_waiting_to_collect_more() {
    struct CountingSink {
        output: Arc<Mutex<Vec<u8>>>,
        writes: Arc<AtomicU64>,
        block: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
    }
    impl Write for CountingSink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.writes.fetch_add(1, Ordering::Relaxed);
            if let Some((entered, release)) = self.block.take() {
                entered.send(()).unwrap();
                release.recv().unwrap();
            }
            self.output.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let output = Arc::new(Mutex::new(Vec::new()));
    let writes = Arc::new(AtomicU64::new(0));
    let (entered, blocked) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    let (queue, worker) = ConsoleQueue::start(
        Box::new(CountingSink {
            output: output.clone(),
            writes: writes.clone(),
            block: Some((entered, resume)),
        }),
        RECORDS,
        BYTES,
        MAX_RECORD_BYTES,
    )
    .unwrap();
    assert!(queue.enqueue("first\n".into()));
    // One record is written promptly; batching must not wait for a second.
    blocked.recv_timeout(Duration::from_secs(2)).unwrap();
    for n in 0..100 {
        assert!(queue.enqueue(format!("record-{n}\n")));
    }
    release.send(()).unwrap();
    assert!(queue.flush(Duration::from_secs(2)));
    assert_eq!(writes.load(Ordering::Relaxed), 3); // 1 + 64 + 36 records.
    assert_eq!(queue.counters.snapshot().queued_bytes, 0);
    assert_eq!(queue.counters.snapshot().dropped_records, 0);
    drop(queue);
    worker.join().unwrap();
    let expected = "first\n".to_owned()
        + &(0..100)
            .map(|n| format!("record-{n}\n"))
            .collect::<String>();
    assert_eq!(*output.lock().unwrap(), expected.as_bytes());
}

#[test]
fn batches_do_not_cross_flush_and_keep_byte_credit_during_partial_writes() {
    struct PartialSink {
        output: Arc<Mutex<Vec<u8>>>,
        flushes: Arc<Mutex<Vec<Vec<u8>>>>,
        block: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
    }
    impl Write for PartialSink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some((entered, release)) = self.block.take() {
                entered.send(()).unwrap();
                release.recv().unwrap();
            }
            let length = bytes.len().min(3);
            self.output
                .lock()
                .unwrap()
                .extend_from_slice(&bytes[..length]);
            Ok(length)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes
                .lock()
                .unwrap()
                .push(self.output.lock().unwrap().clone());
            Ok(())
        }
    }
    let output = Arc::new(Mutex::new(Vec::new()));
    let flushes = Arc::new(Mutex::new(Vec::new()));
    let (entered, blocked) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    let (queue, worker) = ConsoleQueue::start(
        Box::new(PartialSink {
            output: output.clone(),
            flushes: flushes.clone(),
            block: Some((entered, resume)),
        }),
        16,
        1024,
        100,
    )
    .unwrap();
    assert!(queue.enqueue("first\n".into()));
    blocked.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(queue.enqueue("before\n".into()));
    let (reply, result) = mpsc::channel();
    queue.sender.try_send(Command::Flush(reply)).ok().unwrap();
    assert!(queue.enqueue("after\n".into()));
    assert_eq!(queue.counters.snapshot().queued_bytes, 19);
    release.send(()).unwrap();
    assert!(result.recv_timeout(Duration::from_secs(2)).unwrap());
    drop(queue);
    worker.join().unwrap();
    assert_eq!(flushes.lock().unwrap()[0], b"first\nbefore\n");
    assert_eq!(*output.lock().unwrap(), b"first\nbefore\nafter\n");
}
