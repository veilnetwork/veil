use std::path::{Path, PathBuf};

use veil_cfg;

use super::handlers::ConfigOps;
use super::output::{CommandIo, OutputEvent, OutputRenderer, TextRenderer};

#[derive(Debug, Default)]
pub(crate) struct BufferIo {
    pub(crate) output: String,
}

impl CommandIo for BufferIo {
    fn emit(&mut self, event: OutputEvent) {
        self.output.push_str(&TextRenderer::render(&event));
    }
}

#[derive(Debug, Default)]
pub(crate) struct MockConfigOps {
    pub(crate) locate_path: PathBuf,
    pub(crate) raw_config: String,
    pub(crate) loaded_config: veil_cfg::Config,
}

impl ConfigOps for MockConfigOps {
    fn default_init_path(&self) -> PathBuf {
        PathBuf::from("/tmp/default-config.toml")
    }

    fn prepare_init_path(&self, path: &Path, _force: bool) -> veil_cfg::Result<PathBuf> {
        Ok(path.to_path_buf())
    }

    fn locate_config(&self, _config_arg: Option<&Path>) -> veil_cfg::Result<PathBuf> {
        Ok(self.locate_path.clone())
    }

    fn read_raw_config(&self, _path: &Path) -> veil_cfg::Result<String> {
        Ok(self.raw_config.clone())
    }

    fn load_config(&self, _path: &Path) -> veil_cfg::Result<veil_cfg::Config> {
        Ok(self.loaded_config.clone())
    }

    fn save_config(&self, _path: &Path, _config: &veil_cfg::Config) -> veil_cfg::Result<()> {
        Ok(())
    }

    fn write_raw_config(&self, _path: &Path, _content: &str) -> veil_cfg::Result<()> {
        // Slice 11b: test stub.  Real adapter atomically writes to
        // disk; the fixture just acks.
        Ok(())
    }
}
