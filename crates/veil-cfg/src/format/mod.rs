pub(crate) mod json;
pub(crate) mod toml;

use crate::{Config, FileFormat, Result};

pub(crate) const GLOBAL_SECTION: &str = "global";
pub(crate) const IDENTITY_SECTION: &str = "Identity";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SaveStrategy {
    Rewrite,
    PatchExisting,
}

pub(crate) trait FormatBackend {
    fn load(&self, content: &str) -> Result<Config>;

    fn save_strategy(&self) -> SaveStrategy {
        SaveStrategy::Rewrite
    }

    fn render(&self, config: &Config) -> Result<String>;

    fn patch_existing(&self, _content: &str, config: &Config) -> Result<String> {
        self.render(config)
    }
}

pub(crate) fn backend(format: FileFormat) -> &'static dyn FormatBackend {
    match format {
        FileFormat::Toml => &toml::BACKEND,
        FileFormat::Json => &json::BACKEND,
    }
}
