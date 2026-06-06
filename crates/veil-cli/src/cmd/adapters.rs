use std::path::{Path, PathBuf};

use veil_cfg;

use super::{
    handlers::{CommandContext, ConfigOps},
    output::{OutputFormat, StdCommandIo},
};

#[derive(Debug)]
pub struct StdConfigOps;

#[derive(Debug)]
pub struct CliRuntime<'a> {
    pub context: CommandContext<'a, StdCommandIo, StdConfigOps>,
}

impl<'a> CliRuntime<'a> {
    pub fn new(config_arg: Option<&'a Path>, output_format: OutputFormat) -> Self {
        Self {
            context: CommandContext {
                config_arg,
                io: StdCommandIo::new(output_format),
                ops: StdConfigOps,
            },
        }
    }
}

impl ConfigOps for StdConfigOps {
    fn default_init_path(&self) -> PathBuf {
        veil_cfg::default_init_path()
    }

    fn prepare_init_path(&self, path: &Path, force: bool) -> veil_cfg::Result<PathBuf> {
        veil_cfg::prepare_init_path(path, force)
    }

    fn locate_config(&self, config_arg: Option<&Path>) -> veil_cfg::Result<PathBuf> {
        veil_cfg::locate_config(config_arg)
    }

    fn read_raw_config(&self, path: &Path) -> veil_cfg::Result<String> {
        veil_cfg::read_raw_config(path)
    }

    fn load_config(&self, path: &Path) -> veil_cfg::Result<veil_cfg::Config> {
        veil_cfg::load_config(path)
    }

    fn save_config(&self, path: &Path, config: &veil_cfg::Config) -> veil_cfg::Result<()> {
        veil_cfg::save_config(path, config)
    }

    fn write_raw_config(&self, path: &Path, content: &str) -> veil_cfg::Result<()> {
        // Atomic write via `veil_util::atomic_write` — writes to a
        // temp file alongside the target, fsyncs, then renames.  Same
        // primitive `veil_cfg::save_config` uses internally, so the
        // crash-safety story is identical.
        veil_util::atomic_write(path, content.as_bytes()).map_err(|e| {
            veil_cfg::ConfigError::CommandFailed(format!(
                "write_raw_config {}: {e}",
                path.display()
            ))
        })
    }
}
