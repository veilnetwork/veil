//! App endpoint addresses must be derived from the IDENTITY, not this device.
//!
//! `app_id` is the address a peer SENDS TO. A sender derives it from the
//! address it holds for the recipient — an invite, a certificate, a contact row
//! — and all three carry the identity. Deriving the listener's half from the
//! device meant the two halves of one formula ran on different inputs and never
//! met: `app.rt_control.route … routed=false` on every call-signalling frame,
//! `realtimeRxCount: 0` for a whole run, the callee `active` and the caller
//! still `dialing`.
//!
//! Guarded from outside the file it guards, so the needle is not its own proof.

const IPC_SERVER: &str = include_str!("../src/runtime/ipc_server.rs");

/// The value handed to the IPC server must come from the sovereign document.
#[test]
fn the_ipc_server_binds_under_the_sovereign_node_id() {
    assert!(
        IPC_SERVER.contains(".map(|sov| *sov.node_id())"),
        "the bind id must be read off the sovereign document",
    );
    assert!(
        IPC_SERVER.contains(".unwrap_or(node_id)"),
        "a node with no document IS its own identity and must still bind",
    );
}

/// Handing the device id straight through is the defect.
#[test]
fn the_bind_id_reaches_the_server() {
    assert!(
        IPC_SERVER.contains(".with_bind_node_id(bind_node_id)"),
        "the bind id must actually reach the IPC server",
    );
}

/// Both ids are logged. An ordering change that ever put the IPC server before
/// the identity promotion would otherwise be silent — and it would present as
/// "calls do not connect", three layers away from its cause.
#[test]
fn the_start_line_names_both_ids() {
    assert!(
        IPC_SERVER.contains("app_ids_under={} (device {})"),
        "ipc.start must say which id endpoints were bound under",
    );
}
