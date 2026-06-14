use std::path::Path;

use super::{ConfigError, Result};

const SUPPORTED_EXTENSIONS: [&str; 2] = ["toml", "json"];

/// On-disk serialisation format for the veil config file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileFormat {
    /// TOML — preferred, human-edited.
    Toml,
    /// JSON — used by tooling that expects a machine-friendly format.
    Json,
}

impl FileFormat {
    /// Infer the format from the path's extension (`.toml` or `.json`).
    /// Any other extension returns [`ConfigError::UnsupportedFormat`].
    pub fn from_path(path: &Path) -> Result<Self> {
        let ext = path
            .extension()
            .and_then(|value| value.to_str())
            .ok_or_else(|| ConfigError::UnsupportedFormat(path.display().to_string()))?;

        match ext {
            "toml" => Ok(Self::Toml),
            "json" => Ok(Self::Json),
            _ => Err(ConfigError::UnsupportedFormat(path.display().to_string())),
        }
    }

    /// The list of file extensions recognised by [`Self::from_path`].
    pub fn supported_extensions() -> &'static [&'static str] {
        &SUPPORTED_EXTENSIONS
    }
}
