use crate::identity_ops::IdentityRepairPlan;
use crate::identity_policy::PowPolicy;
use crate::{Config, DomainIdentity};

use super::report::ValidationIssue;

pub struct IdentityValidationRule {
    pub code: &'static str,
    pub key: &'static str,
    pub message: fn(&PowPolicy) -> String,
    pub check: fn(&Config, &PowPolicy) -> bool,
    pub repair: Option<IdentityRepairPlan>,
}

pub const IDENTITY_RULES: &[IdentityValidationRule] = &[
    // Audit cycle-9: surface UNDECODABLE key material. The signature / nonce
    // rules below `DomainIdentity::from_config(..).ok()` then `is_some_and`, so
    // a corrupt keypair (unparseable base64 / wrong length for the algo) maps to
    // None and those rules silently DON'T fire — `validate` reported "OK" on a
    // config the daemon then crashes loading at startup. This rule fires exactly
    // when the identity section is present but cannot be decoded.
    IdentityValidationRule {
        code: "identity_keypair_decodable",
        key: "Identity",
        message: identity_undecodable_message,
        check: identity_undecodable,
        repair: None, // corrupt key material can't be auto-repaired
    },
    IdentityValidationRule {
        code: "identity_signature_valid",
        key: "Identity",
        message: identity_signature_message,
        check: identity_signature_invalid,
        repair: Some(IdentityRepairPlan::RegenerateKeysAndNonce),
    },
    IdentityValidationRule {
        code: "identity_nonce_has_leading_zero",
        key: "identity.nonce",
        message: identity_nonce_message,
        check: identity_nonce_missing_leading_zero,
        repair: Some(IdentityRepairPlan::RecomputeNonce),
    },
];

pub fn collect_issues(config: &Config, pow: &PowPolicy) -> Vec<ValidationIssue> {
    IDENTITY_RULES
        .iter()
        .filter(|rule| (rule.check)(config, pow))
        .map(|rule| ValidationIssue {
            code: rule.code,
            key: rule.key,
            message: (rule.message)(pow),
            can_fix: rule.repair.is_some(),
        })
        .collect()
}

pub fn collect_repairs(config: &Config, pow: &PowPolicy) -> Vec<IdentityRepairPlan> {
    IDENTITY_RULES
        .iter()
        .filter(|rule| (rule.check)(config, pow))
        .filter_map(|rule| rule.repair)
        .collect()
}

fn identity_undecodable_message(_pow: &PowPolicy) -> String {
    "identity key material must decode: base64 public_key / private_key / nonce \
     must parse and match the configured algo"
        .to_owned()
}

fn identity_undecodable(config: &Config, _pow: &PowPolicy) -> bool {
    config
        .identity
        .as_ref()
        .is_some_and(|identity| DomainIdentity::from_config(identity).is_err())
}

fn identity_signature_message(_pow: &PowPolicy) -> String {
    "must sign and verify with the configured keypair".to_owned()
}

fn identity_nonce_message(pow: &PowPolicy) -> String {
    format!("must produce at least {} leading zero bits", pow.difficulty)
}

fn identity_signature_invalid(config: &Config, _pow: &PowPolicy) -> bool {
    config
        .identity
        .as_ref()
        .and_then(|identity| DomainIdentity::from_config(identity).ok())
        .is_some_and(|identity| !crate::identity::identity_signature_is_valid(&identity))
}

fn identity_nonce_missing_leading_zero(config: &Config, pow: &PowPolicy) -> bool {
    config
        .identity
        .as_ref()
        .and_then(|identity| DomainIdentity::from_config(identity).ok())
        .is_some_and(|identity| {
            !crate::identity::identity_nonce_meets_difficulty(&identity, pow.difficulty)
        })
}
