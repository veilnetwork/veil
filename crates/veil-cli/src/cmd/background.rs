use std::sync::mpsc;
use std::time::Duration;

use veil_cfg;
use veil_crypto;

use super::output::CommandIo;

pub(super) struct PowTaskRunner;

impl PowTaskRunner {
    pub(super) fn run<I, T, Task, OnProgress>(
        io: &mut I,
        task: Task,
        mut on_progress: OnProgress,
    ) -> veil_cfg::Result<T>
    where
        I: CommandIo,
        T: Send + 'static,
        Task:
            FnOnce(mpsc::Sender<veil_crypto::PowProgress>) -> veil_cfg::Result<T> + Send + 'static,
        OnProgress: FnMut(&mut I, veil_crypto::PowProgress),
    {
        let (progress_tx, progress_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::sync_channel(1);

        std::thread::spawn(move || {
            let result = task(progress_tx);
            let _ = result_tx.send(result);
        });

        Self::await_result(io, progress_rx, result_rx, &mut on_progress)
    }

    fn await_result<I, T, OnProgress>(
        io: &mut I,
        progress_rx: mpsc::Receiver<veil_crypto::PowProgress>,
        result_rx: mpsc::Receiver<veil_cfg::Result<T>>,
        on_progress: &mut OnProgress,
    ) -> veil_cfg::Result<T>
    where
        I: CommandIo,
        OnProgress: FnMut(&mut I, veil_crypto::PowProgress),
    {
        loop {
            Self::drain_progress(io, &progress_rx, on_progress);

            match result_rx.recv_timeout(Duration::from_millis(50)) {
                Ok(result) => {
                    Self::drain_progress(io, &progress_rx, on_progress);
                    return result;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(veil_cfg::ConfigError::PowWorkerDisconnected);
                }
            }
        }
    }

    fn drain_progress<I, OnProgress>(
        io: &mut I,
        progress_rx: &mpsc::Receiver<veil_crypto::PowProgress>,
        on_progress: &mut OnProgress,
    ) where
        I: CommandIo,
        OnProgress: FnMut(&mut I, veil_crypto::PowProgress),
    {
        for progress in progress_rx.try_iter() {
            on_progress(io, progress);
        }
    }
}
