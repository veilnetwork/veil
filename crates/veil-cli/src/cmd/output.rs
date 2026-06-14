use std::fmt;
use std::path::PathBuf;

use clap::ValueEnum;
use serde::Serialize;

use veil_cfg::{IdentityConfig, SignatureAlgorithm};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PowResultStatus {
    Found,
    Timeout,
    Interrupted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SupportedAlgorithmView {
    pub algorithm: SignatureAlgorithm,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IdentityView {
    pub algo: SignatureAlgorithm,
    pub public_key: String,
    pub private_key: String,
    pub nonce: String,
}

impl From<&IdentityConfig> for IdentityView {
    fn from(value: &IdentityConfig) -> Self {
        Self {
            algo: value.algo,
            public_key: value.public_key.clone(),
            private_key: value.private_key.clone(),
            nonce: value.nonce.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OutputEvent {
    ConfigPath {
        path: PathBuf,
    },
    ConfigContents {
        content: String,
    },
    Message {
        message: String,
    },
    ValidationPassed,
    ValidationFixed {
        fixed: usize,
    },
    ConfigValue {
        value: String,
    },
    SupportedAlgorithm(SupportedAlgorithmView),
    Identity(IdentityView),
    PowProgress {
        nonce: String,
        leading_zero_bits: u32,
    },
    PowResult {
        nonce: String,
        stopped_at: String,
        leading_zero_bits: u32,
        status: PowResultStatus,
    },
}

impl OutputEvent {
    pub fn config_path(path: impl Into<PathBuf>) -> Self {
        Self::ConfigPath { path: path.into() }
    }

    pub fn config_contents(content: impl Into<String>) -> Self {
        Self::ConfigContents {
            content: content.into(),
        }
    }

    pub fn message(message: impl Into<String>) -> Self {
        Self::Message {
            message: message.into(),
        }
    }

    pub fn validation_fixed(fixed: usize) -> Self {
        Self::ValidationFixed { fixed }
    }

    pub fn config_value(value: impl Into<String>) -> Self {
        Self::ConfigValue {
            value: value.into(),
        }
    }

    pub fn supported_algorithm(algorithm: SignatureAlgorithm) -> Self {
        Self::SupportedAlgorithm(SupportedAlgorithmView { algorithm })
    }

    pub fn identity(identity: impl Into<IdentityView>) -> Self {
        Self::Identity(identity.into())
    }

    pub fn pow_progress(nonce: impl Into<String>, leading_zero_bits: u32) -> Self {
        Self::PowProgress {
            nonce: nonce.into(),
            leading_zero_bits,
        }
    }

    pub fn pow_result(
        nonce: impl Into<String>,
        stopped_at: impl Into<String>,
        leading_zero_bits: u32,
        status: PowResultStatus,
    ) -> Self {
        Self::PowResult {
            nonce: nonce.into(),
            stopped_at: stopped_at.into(),
            leading_zero_bits,
            status,
        }
    }
}

pub trait OutputRenderer {
    fn render(event: &OutputEvent) -> String;
}

pub struct TextRenderer;
pub struct JsonLinesRenderer;

struct TextLine<T>(T);

struct ValidationFixedText {
    fixed: usize,
}

struct PowProgressText<'a> {
    nonce: &'a str,
    leading_zero_bits: u32,
}

struct PowResultText<'a> {
    nonce: &'a str,
    stopped_at: &'a str,
    leading_zero_bits: u32,
    status: PowResultStatus,
}

impl<T: fmt::Display> fmt::Display for TextLine<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.0)
    }
}

impl fmt::Display for ValidationFixedText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.fixed > 0 {
            writeln!(f, "config is valid; fixed {} issue(s)", self.fixed)
        } else {
            writeln!(f, "config is valid; no fixes were required")
        }
    }
}

impl fmt::Display for IdentityView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "algo: {}", self.algo)?;
        writeln!(f, "public_key: {}", self.public_key)?;
        writeln!(f, "private_key: {}", self.private_key)?;
        writeln!(f, "nonce: {}", self.nonce)
    }
}

impl fmt::Display for PowResultStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            PowResultStatus::Found => "found",
            PowResultStatus::Timeout => "timeout",
            PowResultStatus::Interrupted => "interrupted",
        };
        f.write_str(value)
    }
}

impl fmt::Display for PowProgressText<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "progress: nonce={} leading_zero_bits={}",
            self.nonce, self.leading_zero_bits
        )
    }
}

impl fmt::Display for PowResultText<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "nonce: {}", self.nonce)?;
        writeln!(f, "stopped_at: {}", self.stopped_at)?;
        writeln!(f, "leading_zero_bits: {}", self.leading_zero_bits)?;
        writeln!(f, "status: {}", self.status)
    }
}

fn render_text(value: impl fmt::Display) -> String {
    value.to_string()
}

impl OutputEvent {
    fn render_text(&self) -> String {
        match self {
            OutputEvent::ConfigPath { path } => render_text(TextLine(path.display())),
            OutputEvent::ConfigContents { content } => content.clone(),
            OutputEvent::Message { message } => render_text(TextLine(message)),
            OutputEvent::ValidationPassed => "config is valid\n".to_owned(),
            OutputEvent::ValidationFixed { fixed } => {
                render_text(ValidationFixedText { fixed: *fixed })
            }
            OutputEvent::ConfigValue { value } => render_text(TextLine(value)),
            OutputEvent::SupportedAlgorithm(SupportedAlgorithmView { algorithm }) => {
                render_text(TextLine(algorithm))
            }
            OutputEvent::Identity(identity) => render_text(identity),
            OutputEvent::PowProgress {
                nonce,
                leading_zero_bits,
            } => render_text(PowProgressText {
                nonce,
                leading_zero_bits: *leading_zero_bits,
            }),
            OutputEvent::PowResult {
                nonce,
                stopped_at,
                leading_zero_bits,
                status,
            } => render_text(PowResultText {
                nonce,
                stopped_at,
                leading_zero_bits: *leading_zero_bits,
                status: *status,
            }),
        }
    }
}

impl OutputRenderer for TextRenderer {
    fn render(event: &OutputEvent) -> String {
        event.render_text()
    }
}

impl OutputRenderer for JsonLinesRenderer {
    fn render(event: &OutputEvent) -> String {
        let line = match serde_json::to_string(event) {
            Ok(line) => line,
            Err(err) => {
                let escaped = serde_json::to_string(&err.to_string())
                    .unwrap_or_else(|_| "\"output serialization error\"".to_owned());
                format!("{{\"type\":\"serialization_error\",\"message\":{escaped}}}")
            }
        };
        format!("{line}\n")
    }
}

pub(super) fn format_columns(columns: &[&str], widths: &[usize]) -> String {
    columns
        .iter()
        .zip(widths.iter())
        .map(|(value, width)| {
            if *width == 0 {
                (*value).to_owned()
            } else {
                format!("{value:<width$}")
            }
        })
        .collect::<Vec<_>>()
        .join("  ")
}

pub trait CommandIo {
    fn emit(&mut self, event: OutputEvent);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    JsonLines,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum OutputFormatArg {
    Text,
    Jsonl,
}

impl From<OutputFormatArg> for OutputFormat {
    fn from(value: OutputFormatArg) -> Self {
        match value {
            OutputFormatArg::Text => Self::Text,
            OutputFormatArg::Jsonl => Self::JsonLines,
        }
    }
}

#[derive(Debug)]
pub struct StdCommandIo {
    format: OutputFormat,
}

impl StdCommandIo {
    pub fn new(format: OutputFormat) -> Self {
        Self { format }
    }
}

impl Default for StdCommandIo {
    fn default() -> Self {
        Self::new(OutputFormat::Text)
    }
}

impl CommandIo for StdCommandIo {
    fn emit(&mut self, event: OutputEvent) {
        let rendered = match self.format {
            OutputFormat::Text => TextRenderer::render(&event),
            OutputFormat::JsonLines => JsonLinesRenderer::render(&event),
        };
        print!("{rendered}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_cfg::SignatureAlgorithm;

    #[test]
    fn json_renderer_serializes_semantic_events() {
        let rendered = JsonLinesRenderer::render(&OutputEvent::pow_result(
            "AAAAAA==",
            "AAAABQ==",
            17,
            PowResultStatus::Found,
        ));
        assert!(rendered.contains("\"type\":\"pow_result\""));
        assert!(rendered.contains("\"leading_zero_bits\":17"));
    }

    #[test]
    fn text_renderer_formats_identity_event() {
        let rendered = TextRenderer::render(&OutputEvent::identity(IdentityView {
            algo: SignatureAlgorithm::Ed25519,
            public_key: "pub".to_owned(),
            private_key: "priv".to_owned(),
            nonce: "AAAAAA==".to_owned(),
        }));

        assert_eq!(
            rendered,
            "algo: ed25519\npublic_key: pub\nprivate_key: priv\nnonce: AAAAAA==\n"
        );
    }

    #[test]
    fn text_renderer_formats_validation_fixed_event() {
        let rendered = TextRenderer::render(&OutputEvent::validation_fixed(2));
        assert_eq!(rendered, "config is valid; fixed 2 issue(s)\n");
    }

    #[test]
    fn text_renderer_formats_pow_result_event() {
        let rendered = TextRenderer::render(&OutputEvent::pow_result(
            "AAAAAA==",
            "AAAABQ==",
            17,
            PowResultStatus::Found,
        ));

        assert_eq!(
            rendered,
            "nonce: AAAAAA==\nstopped_at: AAAABQ==\nleading_zero_bits: 17\nstatus: found\n"
        );
    }
}
