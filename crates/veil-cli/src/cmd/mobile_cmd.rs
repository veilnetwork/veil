//! CLI handler for `veil-cli mobile …`.
//!
//! Operator-visible front-end for the mobile-mode runtime flags
//! that GUI wrappers normally drive via the IPC API. Useful for:
//! * Mobile app integrators testing their integration without
//!   writing IPC code.
//! * Cron-based cellular saving (flip background mode at night).
//! * Headless deployments where the daemon acts as a mobile
//!   gateway.
//!
//! Sends an admin request — requires a running node. The
//! `update` command doesn't need an admin
//! socket because its check/apply paths run against the operator's
//! HTTPS endpoints directly, but mobile-mode controls toggle
//! per-process runtime state so the daemon must be alive to
//! receive them.

use tokio::runtime::Builder;

use veil_cfg;
use veil_node_runtime::admin as node;

use super::{
    cli::{MobileArgs, MobileCommand},
    handlers::{CommandContext, ConfigOps},
    output::{CommandIo, OutputEvent},
    util::map_node_error,
};

pub fn handle_mobile_command<I: CommandIo, O: ConfigOps>(
    mut context: CommandContext<'_, I, O>,
    args: MobileArgs,
) -> veil_cfg::Result<()> {
    match args.command {
        MobileCommand::BackgroundMode { state } => background_mode(&mut context, state.as_bool()),
    }
}

fn background_mode<I: CommandIo, O: ConfigOps>(
    context: &mut CommandContext<'_, I, O>,
    enabled: bool,
) -> veil_cfg::Result<()> {
    let (config_path, config) = context.config().load_existing()?;
    if config.global.admin_socket.is_none() {
        return Err(veil_cfg::ConfigError::CommandFailed(
            "global.admin_socket must be configured (mobile-mode controls toggle \
             per-process runtime state — daemon must be alive to receive them)"
                .to_owned(),
        ));
    }
    let socket = node::admin_socket_path(&config, config_path.parent()).map_err(map_node_error)?;
    if !node::admin_anchor_reachable_sync(&socket) {
        return Err(veil_cfg::ConfigError::CommandFailed(format!(
            "admin socket `{}` was not found; start the node with `veil-cli node run`",
            socket.display()
        )));
    }

    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(veil_cfg::ConfigError::Io)?;
    let response = runtime
        .block_on(node::send_request(
            &socket,
            node::AdminCommand::SetMobileBackgroundMode { enabled },
        ))
        .map_err(map_node_error)?;

    if let Some(error) = response.error {
        return Err(veil_cfg::ConfigError::ValidationFailed(error));
    }
    let Some(node::AdminResult::Ack { message }) = response.result else {
        return Err(veil_cfg::ConfigError::ValidationFailed(
            "admin server returned unexpected response to SetMobileBackgroundMode".to_owned(),
        ));
    };

    // Echo the daemon's confirmation + a concrete "what just changed"
    // line so operators see immediate feedback. When enabled
    // mention the cadence implication so a confused operator who
    // expected instant log activity understands why their keepalive
    // log line just dropped frequency.
    let implication = if enabled {
        " — keepalive cadence stretched per `mobile.background_keepalive_multiplier`; sessions will survive OS suspension"
    } else {
        " — foreground keepalive cadence restored at the next recomputation tick (≤ 60 s)"
    };
    context
        .io
        .emit(OutputEvent::message(format!("{message}{implication}")));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::cli::OnOff;
    use clap::ValueEnum;

    #[test]
    fn epic483_1_on_off_as_bool_round_trip() {
        assert!(OnOff::On.as_bool());
        assert!(!OnOff::Off.as_bool());
    }

    #[test]
    fn epic483_1_on_off_clap_value_enum_parses_canonical_forms() {
        // clap's value_enum derive generates the parser; sanity-check
        // that `on` and `off` both parse as expected so a future
        // refactor that reorders / renames variants is caught.
        let on = OnOff::from_str("on", /* ignore_case */ true).unwrap();
        let off = OnOff::from_str("off", true).unwrap();
        assert!(on.as_bool());
        assert!(!off.as_bool());
    }

    #[test]
    fn epic483_1_on_off_rejects_unknown_input() {
        // `yes` / `enable` / `1` are NOT accepted by clap's value_enum
        // (which is stricter than a custom parser would be). This is
        // a deliberate choice — strict canonical forms reduce the
        // surface for accidental mismatches in shell scripts ("did the
        // operator type 1 meaning on, or 1 meaning the index of the
        // first variant?").
        assert!(OnOff::from_str("yes", true).is_err());
        assert!(OnOff::from_str("enable", true).is_err());
        assert!(OnOff::from_str("1", true).is_err());
    }

    #[test]
    fn epic483_1_on_off_case_insensitive_match() {
        // Operators (and shell completions) may capitalise — `ON` /
        // `OFF` / `On` / `Off` all parse identically to the
        // lowercased canonical forms.
        for truthy in &["on", "ON", "On"] {
            assert!(
                OnOff::from_str(truthy, true).unwrap().as_bool(),
                "must accept `{truthy}` as truthy"
            );
        }
        for falsy in &["off", "OFF", "Off"] {
            assert!(
                !OnOff::from_str(falsy, true).unwrap().as_bool(),
                "must accept `{falsy}` as falsy"
            );
        }
    }
}
