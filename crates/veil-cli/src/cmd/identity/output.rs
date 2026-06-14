use std::path::Path;

use veil_cfg;
use veil_crypto;

use super::super::output::{CommandIo, OutputEvent, PowResultStatus};

pub(super) struct IdentityOutput;

impl IdentityOutput {
    pub(super) fn emit_existing_keys_message(io: &mut impl CommandIo) {
        io.emit(OutputEvent::message(
            "identity keys already exist in the config; use --force to overwrite them",
        ));
    }

    pub(super) fn emit_saved_path(io: &mut impl CommandIo, path: &Path) {
        io.emit(OutputEvent::config_path(path.to_path_buf()));
    }

    pub(super) fn emit_identity(io: &mut impl CommandIo, identity: &veil_cfg::IdentityConfig) {
        io.emit(OutputEvent::identity(identity));
    }

    pub(super) fn emit_supported_algorithms(io: &mut impl CommandIo) {
        for algo in veil_cfg::SignatureAlgorithm::supported() {
            io.emit(OutputEvent::supported_algorithm(*algo));
        }
    }

    pub(super) fn emit_pow_progress(io: &mut impl CommandIo, progress: veil_crypto::PowProgress) {
        io.emit(OutputEvent::pow_progress(
            progress.nonce.as_str(),
            progress.zero_bits,
        ));
    }

    pub(super) fn emit_pow_result(io: &mut impl CommandIo, result: &veil_crypto::PowResult) {
        io.emit(OutputEvent::pow_result(
            result.best_nonce.as_str(),
            result.stopped_at.as_str(),
            result.best_zero_bits,
            match result.stop_reason {
                veil_crypto::PowStopReason::Found => PowResultStatus::Found,
                veil_crypto::PowStopReason::Timeout => PowResultStatus::Timeout,
                veil_crypto::PowStopReason::Interrupted => PowResultStatus::Interrupted,
            },
        ));
    }
}
