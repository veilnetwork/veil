use base64::{Engine as _, engine::general_purpose::STANDARD};

use veil_error::{ConfigError, Result};
use veil_types::SignatureAlgorithm;

#[derive(Clone, PartialEq, Eq)]
pub struct Base64PublicKey(String);

// redact key material in Debug output to prevent accidental leakage.
impl std::fmt::Debug for Base64PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Base64PublicKey")
            .field(&"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Base64PrivateKey(String);

impl std::fmt::Debug for Base64PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Base64PrivateKey")
            .field(&"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Base64Nonce(String);

impl Base64PublicKey {
    pub fn new(algo: SignatureAlgorithm, value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_public_key(algo, &value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl Base64PrivateKey {
    pub fn new(algo: SignatureAlgorithm, value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_private_key(algo, &value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl Base64Nonce {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let bytes = STANDARD.decode(&value)?;
        let actual = bytes.len();
        let _: [u8; 4] = bytes
            .try_into()
            .map_err(|_| ConfigError::InvalidNonceLength {
                expected: 4,
                actual,
            })?;
        Ok(Self(value))
    }

    pub fn zero() -> Self {
        Self(STANDARD.encode([0_u8; 4]))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

fn validate_public_key(algo: SignatureAlgorithm, value: &str) -> Result<()> {
    // hybrid validates each component; delegate to the
    // canonical decode_public_key in signature.rs to avoid duplicating
    // the split + re-validate logic here.
    super::signature::decode_public_key(algo, value).map(|_| ())
}

fn validate_private_key(algo: SignatureAlgorithm, value: &str) -> Result<()> {
    super::signature::decode_private_key(algo, value).map(|_| ())
}
