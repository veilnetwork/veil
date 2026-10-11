//! Optional debug-build counters for nonblocking local admission failures.
//! RTP callbacks only increment atomics. File I/O runs on a separate thread,
//! enabled explicitly by the stand before opening a channel. No wire labels,
//! packet contents, addresses, channel identifiers or keys are recorded.

#[derive(Clone, Copy)]
pub(super) enum Reason {
    RegistryBusy,
    UnknownChannel,
    IngressClosed,
    MissingScreen,
    AssemblerBusy,
    IncompleteFrame,
    PacketQueueFull,
    PacketQueueClosed,
    FrameQueueFull,
    FrameQueueClosed,
}

pub(super) fn refuse(reason: Reason, secondary: bool, code: i32) -> i32 {
    #[cfg(debug_assertions)]
    COUNTERS[reason as usize * 2 + usize::from(secondary)]
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    #[cfg(not(debug_assertions))]
    let _ = (reason, secondary);
    code
}

#[cfg(debug_assertions)]
static COUNTERS: [std::sync::atomic::AtomicU64; 20] =
    [const { std::sync::atomic::AtomicU64::new(0) }; 20];

#[cfg(debug_assertions)]
pub(super) fn snapshot() -> [u64; 20] {
    std::array::from_fn(|i| COUNTERS[i].load(std::sync::atomic::Ordering::Relaxed))
}

pub(super) fn start() {
    #[cfg(debug_assertions)]
    {
        static START: std::sync::Once = std::sync::Once::new();
        START.call_once(|| {
            let Some(path) = std::env::var_os("VEIL_MEDIA_INGRESS_DIAG_PATH") else {
                return;
            };
            let _ = std::thread::Builder::new()
                .name("veil-media-ingress-diag".into())
                .spawn(move || {
                    use std::io::Write;
                    #[cfg(unix)]
                    use std::os::unix::fs::OpenOptionsExt;
                    let mut options = std::fs::OpenOptions::new();
                    options.create(true).append(true);
                    #[cfg(unix)]
                    options.mode(0o600);
                    let Ok(mut file) = options.open(path) else {
                        return;
                    };
                    const NAMES: [&str; 10] = [
                        "registry_busy",
                        "unknown_channel",
                        "ingress_closed",
                        "missing_screen",
                        "assembler_busy",
                        "incomplete_frame",
                        "packet_queue_full",
                        "packet_queue_closed",
                        "frame_queue_full",
                        "frame_queue_closed",
                    ];
                    let mut previous = None;
                    loop {
                        let counts = snapshot();
                        if previous != Some(counts) {
                            let values: serde_json::Map<String, serde_json::Value> = NAMES
                                .iter()
                                .enumerate()
                                .flat_map(|(i, name)| {
                                    ["primary", "secondary"].iter().enumerate().map(
                                        move |(j, source)| {
                                            (format!("{name}_{source}"), counts[i * 2 + j].into())
                                        },
                                    )
                                })
                                .collect();
                            if writeln!(file, "{}", serde_json::Value::Object(values)).is_err() {
                                return;
                            }
                            previous = Some(counts);
                        }
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    }
                });
        });
    }
}
