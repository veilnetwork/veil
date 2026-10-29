//! Opt-in endpoint preparation timings. No addresses, keys or payload fields.
use std::{sync::Arc, time::Instant};
use veil_observability::NodeLogger;

#[derive(Clone, Copy)]
pub(super) enum Stage {
    ReceiverAds,
    RelayDirectory,
    DirectoryWarmLock,
    DirectoryWarm,
    CircuitOpen,
}

impl Stage {
    fn label(self) -> &'static str {
        match self {
            Self::ReceiverAds => "receiver_ads",
            Self::RelayDirectory => "relay_directory",
            Self::DirectoryWarmLock => "directory_warm_lock",
            Self::DirectoryWarm => "directory_warm",
            Self::CircuitOpen => "circuit_open",
        }
    }
}

pub(super) struct Trace {
    started: Option<Instant>,
    logger: Option<Arc<NodeLogger>>,
    stage: Stage,
    result: u8,
    local: bool,
    address_kind: u8,
    count: usize,
}

impl Trace {
    pub(super) fn enabled(&self) -> bool {
        self.started.is_some()
    }

    pub(super) fn new(logger: &Arc<NodeLogger>, stage: Stage) -> Self {
        let enabled = veil_session::rt_trace::rt_trace_enabled();
        Self {
            started: enabled.then(Instant::now),
            logger: enabled.then(|| Arc::clone(logger)),
            stage,
            result: 0, // incomplete: cancellation or early error, not a verdict
            local: false,
            address_kind: 0, // unknown; 1 identity, 2 verified local device hint
            count: 0,
        }
    }

    pub(super) fn finish(&mut self, found: bool, count: usize) {
        self.result = if found { 1 } else { 2 };
        self.count = count;
    }

    pub(super) fn local(&mut self) {
        self.local = true;
    }

    pub(super) fn address_kind(&mut self, kind: u8) {
        self.address_kind = kind.min(2);
    }

    fn sample(&self, elapsed_ms: u64) -> String {
        format!(
            "stage={} elapsed_ms={} result={} local={} address_kind={} count={}",
            self.stage.label(),
            elapsed_ms,
            self.result,
            u8::from(self.local),
            self.address_kind,
            self.count,
        )
    }
}

impl Drop for Trace {
    fn drop(&mut self) {
        if let (Some(started), Some(logger)) = (self.started, self.logger.as_ref()) {
            let elapsed_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
            logger.info("onion-stream.stage", self.sample(elapsed_ms));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_only_contain_fixed_stage_names_and_numeric_values() {
        for stage in [
            Stage::ReceiverAds,
            Stage::RelayDirectory,
            Stage::DirectoryWarmLock,
            Stage::DirectoryWarm,
            Stage::CircuitOpen,
        ] {
            let mut trace = Trace {
                started: None,
                logger: None,
                stage,
                result: 0,
                local: false,
                address_kind: 0,
                count: 0,
            };
            assert!(trace.sample(0).contains("result=0"));
            trace.finish(true, 8);
            trace.local();
            trace.address_kind(2);
            let text = trace.sample(3500);
            for (index, field) in text.split_whitespace().enumerate() {
                let (key, value) = field.split_once('=').unwrap();
                assert!(key.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
                if index == 0 {
                    assert_eq!(value, stage.label());
                } else {
                    assert!(value.bytes().all(|b| b.is_ascii_digit()));
                }
            }
            assert!(text.contains("elapsed_ms=3500 result=1 local=1 address_kind=2 count=8"));
            trace.finish(false, 0);
            assert!(trace.sample(0).contains("result=2"));
        }
    }
}
