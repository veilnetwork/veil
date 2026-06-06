//! Canonical error type for the Veil network.
//!
//! Tier 0 leaf crate. Hosts the single shared error enum used
//! across `cfg`, `crypto`, and downstream layers. Each layer
//! that returns `Result<T>` actually returns
//! `Result<T, veil_error::ConfigError>`, preserving the `?`
//! operator chain across crate boundaries.
//!
//! # Why this crate exists
//!
//! Before extraction, `ConfigError` lived in
//! `veilcore::cfg::error`. But `crypto` returns it
//! (`InvalidKeyLength`, `SignatureVerificationFailed`, etc.) and
//! depends on `cfg::Result`, creating a `cfg ↔ crypto` dependency
//! cycle that blocked extraction of either crate. Moving the
//! type here breaks that cycle so `crypto` can become its own
//! crate that depends only on `veil-error` + `veil-types`
//! + `veil-util` (all Tier 0 leaves).
//!
//! # Why the name `ConfigError`
//!
//! Legacy. When the project was small everything error-related
//! lived in `cfg`, hence `ConfigError`. The name stuck even as
//! the enum grew to cover crypto / PoW / identity / ad-hoc CLI
//! failures. A future rename to `VeilError` is on the table
//! but would touch hundreds of call sites; preserved as-is for
//! now via re-export shim from `cfg::error`.

use thiserror::Error;

/// Canonical error type for the Veil network (legacy name —
/// covers config + crypto + ad-hoc command / identity / PoW
/// failures). Wraps upstream errors (`std::io`, `toml`
/// `serde_json`, `base64`) plus internal validation and command
/// failures. Consumers usually see this [`Result`].
#[derive(Debug, Error)]
pub enum ConfigError {
    /// No config file was located by `locate_config`.
    #[error("config was not found")]
    NotFound,
    /// File extension is not one of the supported formats.
    #[error("unsupported config format for `{0}`")]
    UnsupportedFormat(String),
    /// Caller passed a path that does not exist on disk.
    #[error("config path `{0}` does not exist")]
    MissingPath(String),
    /// Target path already exists and `--force` was not specified.
    #[error("config path `{0}` already exists; use --force to overwrite")]
    AlreadyExists(String),
    /// Low-level I/O error while reading or writing the config.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Base64 decode failure in a key / nonce field.
    #[error("base64 error: {0}")]
    Base64(#[from] base64::DecodeError),
    /// TOML parse error.
    #[error("toml error: {0}")]
    Toml(#[from] toml::de::Error),
    /// TOML serialise error when writing the config back out.
    #[error("toml serialize error: {0}")]
    TomlSer(#[from] toml::ser::Error),
    /// TOML patch backend could not re-parse the original document.
    #[error("failed to parse TOML document for patching: {details}")]
    TomlDocumentParse {
        /// Parser-supplied explanation.
        details: String,
    },
    /// A section expected to be a TOML table was a scalar/array/etc.
    #[error("TOML section `{section}` must be a table")]
    TomlSectionNotTable {
        /// Name of the offending section.
        section: &'static str,
    },
    /// An integer value is too large to round-trip through TOML patch logic.
    #[error("TOML integer for `{key}` is out of range for patching: {value}")]
    TomlIntegerOutOfRange {
        /// Config key that carried the out-of-range value.
        key: &'static str,
        /// The offending value (widened to `u128` so both signs fit).
        value: u128,
    },
    /// JSON parse / serialise error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    /// `node config set` rejected `value` for `key`.
    #[error("invalid value `{value}` for `{key}`: {reason}")]
    InvalidValue {
        /// Config key being set.
        key: String,
        /// Raw value supplied by the user.
        value: String,
        /// Why the value was rejected.
        reason: String,
    },
    /// A CLI command reported a human-readable failure.
    #[error("{0}")]
    CommandFailed(String),
    /// Config failed validation; inner string is a multi-line issue dump.
    #[error("config validation failed:\n{0}")]
    ValidationFailed(String),
    /// `node config get`/`set` called with a key not declared in `ConfigKey`.
    #[error("unknown config key `{0}`")]
    UnknownKey(String),
    /// Could not resolve the user's home directory for a default path.
    #[error("unable to determine home directory")]
    HomeDirUnavailable,
    /// A required identity sub-field was absent.
    #[error("identity field `{0}` is missing")]
    MissingIdentityField(&'static str),
    /// An identity field is missing and the user has multiple ways to supply it.
    #[error("identity {field} is missing; pass {cli_flag} or configure {config_key}")]
    MissingIdentityInput {
        /// Name of the missing identity field.
        field: &'static str,
        /// CLI flag the user could pass.
        cli_flag: &'static str,
        /// Config key the user could set.
        config_key: &'static str,
    },
    /// A raw key blob has the wrong length for its declared algorithm.
    #[error("invalid {key_kind} length for `{algo}`: expected {expected} bytes, got {actual}")]
    InvalidKeyLength {
        /// Signature algorithm (e.g. `"ed25519"`).
        algo: String,
        /// Which key kind (`"public"` / `"private"`).
        key_kind: &'static str,
        /// Expected length in bytes.
        expected: usize,
        /// Actual length observed.
        actual: usize,
    },
    /// Decoded nonce does not have the protocol-mandated length.
    #[error("nonce must be exactly {expected} bytes in base64, got {actual}")]
    InvalidNonceLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },
    /// Crypto material (key, public key, signature) failed structural checks.
    #[error("invalid {item} for `{algo}`: {details}")]
    InvalidCryptoMaterial {
        /// Signature algorithm.
        algo: String,
        /// Which material (`"public_key"`, `"signature"`, …).
        item: &'static str,
        /// Parser-supplied explanation.
        details: String,
    },
    /// Signature blob could not be parsed or is malformed.
    #[error("invalid signature for `{algo}`: {details}")]
    InvalidSignature {
        /// Signature algorithm.
        algo: String,
        /// Explanation of the parse failure.
        details: String,
    },
    /// A valid-looking signature failed cryptographic verification.
    #[error("signature verification failed for `{algo}`: {details}")]
    SignatureVerificationFailed {
        /// Signature algorithm.
        algo: String,
        /// Underlying reason provided by the crypto backend.
        details: String,
    },
    /// OS-level failure installing the SIGINT/Ctrl+C handler.
    #[error("failed to install interrupt handler: {0}")]
    InterruptHandlerInstall(String),
    /// A shared-state mutex was found poisoned.
    #[error("shared state `{0}` was poisoned")]
    PoisonedState(&'static str),
    /// User requested a PoW solver with zero worker threads.
    #[error("threads count must be greater than zero")]
    PowThreadsZero,
    /// explicit u32 overflow path — previously conflated with
    /// `PowThreadsZero`, which produced a misleading "must be greater than
    /// zero" message for a thread count that was actually `> u32::MAX`.
    #[error("threads count exceeds u32::MAX (nonce stride overflow)")]
    PowThreadsOverflowU32,
    /// A PoW worker thread panicked while mining.
    #[error("pow worker thread panicked")]
    PowWorkerPanicked,
    /// The PoW worker channel closed before emitting a result.
    #[error("pow worker disconnected before returning a result")]
    PowWorkerDisconnected,
}

/// Shorthand alias for `Result<T, ConfigError>` used throughout `cfg`.
pub type Result<T> = std::result::Result<T, ConfigError>;
