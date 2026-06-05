use veil_cfg;
use veil_cfg::identity_ops::{
    IdentityPowParams, IdentityProvisionParams, IdentityUseCases, VerifiedKeyMaterial,
};
use veil_crypto;

use super::super::background::PowTaskRunner;
use super::super::output::CommandIo;
use super::output::IdentityOutput;
use super::types::KeyMaterial;

pub(super) struct IdentityProgressRunner;

impl IdentityProgressRunner {
    pub(super) fn provision_identity(
        io: &mut impl CommandIo,
        params: IdentityProvisionParams,
    ) -> veil_cfg::Result<veil_cfg::IdentityConfig> {
        let use_cases = IdentityUseCases::new(params.pow.clone());
        PowTaskRunner::run(
            io,
            move |progress_tx| use_cases.provision(params.algo, Some(progress_tx)),
            IdentityOutput::emit_pow_progress,
        )
    }

    pub(super) fn search_nonce(
        io: &mut impl CommandIo,
        key_material: KeyMaterial,
        start_from: veil_crypto::Base64Nonce,
        pow: IdentityPowParams,
    ) -> veil_cfg::Result<veil_crypto::PowResult> {
        let use_cases = IdentityUseCases::new(pow);
        PowTaskRunner::run(
            io,
            move |progress_tx| {
                use_cases.search_for_verified_key_material(
                    VerifiedKeyMaterial {
                        algo: key_material.algo,
                        public_key: key_material.public_key,
                        private_key: key_material.private_key,
                    },
                    start_from,
                    Some(progress_tx),
                )
            },
            IdentityOutput::emit_pow_progress,
        )
    }
}
