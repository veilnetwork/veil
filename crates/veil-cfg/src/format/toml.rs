use toml_edit::{DocumentMut, Item, Table, Value, value};

use crate::format::{FormatBackend, GLOBAL_SECTION, IDENTITY_SECTION, SaveStrategy};
use crate::{Config, ConfigError, Result};

pub(crate) static BACKEND: TomlBackend = TomlBackend;
const IDENTITY_SECTION_ALIAS: &str = "identity";

pub(crate) struct TomlBackend;

impl FormatBackend for TomlBackend {
    fn load(&self, content: &str) -> Result<Config> {
        load_config(content)
    }

    fn save_strategy(&self) -> SaveStrategy {
        SaveStrategy::PatchExisting
    }

    fn render(&self, config: &Config) -> Result<String> {
        Ok(toml::to_string_pretty(config)?)
    }

    fn patch_existing(&self, content: &str, config: &Config) -> Result<String> {
        save_existing(content, config)
    }
}

fn load_config(content: &str) -> Result<Config> {
    Ok(toml::from_str(content)?)
}

fn save_existing(content: &str, config: &Config) -> Result<String> {
    let mut document =
        content
            .parse::<DocumentMut>()
            .map_err(|err| ConfigError::TomlDocumentParse {
                details: err.to_string(),
            })?;
    update_document(&mut document, config)?;
    Ok(document.to_string())
}

fn update_document(document: &mut DocumentMut, config: &Config) -> Result<()> {
    let g = &config.global;

    if !document.get(GLOBAL_SECTION).is_some_and(Item::is_table) {
        document[GLOBAL_SECTION] = Item::Table(Table::new());
    }

    let global =
        document[GLOBAL_SECTION]
            .as_table_mut()
            .ok_or(ConfigError::TomlSectionNotTable {
                section: GLOBAL_SECTION,
            })?;
    set_string(global, "runtime_flavor", &g.runtime_flavor.to_string());
    set_integer(global, "worker_threads", g.worker_threads.map(i64::from));
    set_integer(
        global,
        "max_blocking_threads",
        g.max_blocking_threads.map(i64::from),
    );
    set_integer(
        global,
        "thread_keep_alive_ms",
        checked_integer(
            "global.thread_keep_alive_ms",
            g.thread_keep_alive_ms,
            u128::from,
        )?,
    );
    set_string_optional(global, "thread_name", g.thread_name.as_deref());
    set_integer(
        global,
        "thread_stack_size",
        checked_integer("global.thread_stack_size", g.thread_stack_size, |v| {
            v as u128
        })?,
    );
    set_string_optional(global, "admin_socket", g.admin_socket.as_deref());
    set_string(global, "logs", &g.logs.to_string());
    set_string_optional(global, "log_file", g.log_file.as_deref());
    // follow-up + pre-existing-bug fix: previous global-section
    // patcher dropped these fields on save (operator edits the file by
    // hand, runs `node show` or any path that re-saves config, the field
    // silently disappears). Patch them explicitly so set/unset round-
    // trips through `cfg::save_config`.
    set_string_optional(
        global,
        "bootstrap_dns_domain",
        g.bootstrap_dns_domain.as_deref(),
    );
    set_string_optional(
        global,
        "discovered_peers_cache_path",
        g.discovered_peers_cache_path.as_deref(),
    );
    set_string_optional(
        global,
        "trusted_bundle_issuer_pubkey",
        g.trusted_bundle_issuer_pubkey.as_deref(),
    );
    set_string_array(global, "bootstrap_https_urls", &g.bootstrap_https_urls);

    set_transport(document, &config.transport)?;

    match config.identity.as_ref() {
        Some(identity) => {
            let target_section = identity_section_name(document);
            document.remove(other_identity_section_name(target_section));

            if !document.get(target_section).is_some_and(Item::is_table) {
                document[target_section] = Item::Table(Table::new());
            }

            let identity_table = document[target_section].as_table_mut().ok_or(
                ConfigError::TomlSectionNotTable {
                    section: target_section,
                },
            )?;
            set_string(identity_table, "algo", &identity.algo.to_string());
            set_string(identity_table, "public_key", &identity.public_key);
            set_string(identity_table, "private_key", &identity.private_key);
            set_string(identity_table, "nonce", &identity.nonce);
            set_string_optional(
                identity_table,
                "node_id",
                identity.node_id.map(|value| value.to_string()).as_deref(),
            );
            identity_table.remove("names");
        }
        None => {
            document.remove(IDENTITY_SECTION);
            document.remove(IDENTITY_SECTION_ALIAS);
        }
    }

    set_ipc(document, &config.ipc)?;
    set_peers(document, &config.peers);
    set_listens(document, &config.listen);
    set_metrics(document, config.metrics.as_ref());
    set_bootstrap_peers(document, &config.bootstrap_peers);
    Ok(())
}

fn identity_section_name(document: &DocumentMut) -> &'static str {
    if document.get(IDENTITY_SECTION_ALIAS).is_some() && document.get(IDENTITY_SECTION).is_none() {
        IDENTITY_SECTION_ALIAS
    } else {
        IDENTITY_SECTION
    }
}

fn other_identity_section_name(section: &'static str) -> &'static str {
    if section == IDENTITY_SECTION {
        IDENTITY_SECTION_ALIAS
    } else {
        IDENTITY_SECTION
    }
}

fn set_string(table: &mut Table, key: &str, new_value: &str) {
    match table.get_mut(key).and_then(Item::as_value_mut) {
        Some(existing) => replace_value(existing, Value::from(new_value)),
        None => {
            table[key] = value(new_value);
        }
    }
}

fn set_string_optional(table: &mut Table, key: &str, value: Option<&str>) {
    match value {
        Some(value) => set_string(table, key, value),
        None => {
            table.remove(key);
        }
    }
}

/// Patch a `Vec<String>` table entry: empty Vec → remove key (mirrors
/// the `serde::skip_serializing_if = "Vec::is_empty"` annotation), non-
/// empty → write the array. Used for `bootstrap_https_urls` etc.
fn set_string_array(table: &mut Table, key: &str, values: &[String]) {
    if values.is_empty() {
        table.remove(key);
        return;
    }
    let mut array = toml_edit::Array::new();
    for v in values {
        array.push(v.as_str());
    }
    table[key] = value(array);
}

fn set_integer(table: &mut Table, key: &str, new_value: Option<i64>) {
    match new_value {
        Some(new_value) => match table.get_mut(key).and_then(Item::as_value_mut) {
            Some(existing) => replace_value(existing, Value::from(new_value)),
            None => {
                table[key] = value(new_value);
            }
        },
        None => {
            table.remove(key);
        }
    }
}

fn set_transport(document: &mut DocumentMut, transport: &crate::TransportConfig) -> Result<()> {
    // Rotation is **always** emitted (see `TransportConfig::rotation`
    // doc) — its anti-DPI semantics matter enough that operators should
    // discover it by reading their config file even when it's at default.
    // So we don't take the "skip the whole section if default" shortcut
    // anymore — only skip the optional sub-tables (`tls_client`).
    if !document.get("transport").is_some_and(Item::is_table) {
        document["transport"] = Item::Table(Table::new());
    }
    let transport_table =
        document["transport"]
            .as_table_mut()
            .ok_or(ConfigError::TomlSectionNotTable {
                section: "transport",
            })?;

    set_tls_client_table(transport_table, &transport.tls_client)?;
    set_rotation_table(transport_table, &transport.rotation)?;
    set_tls_fingerprint_table(transport_table, &transport.tls_fingerprint)?;
    // Prune sub-tables that are not part of the current schema (e.g.
    // legacy `quic_client` / `websocket` left over from older configs
    // someone copied and updated incrementally).  Pre-Q.7 the entire
    // `[transport]` section was removed-and-rebuilt in the default
    // case, which incidentally cleaned these up; now that we always
    // emit `[transport.rotation]`, we have to do the pruning explicitly.
    //
    // `tls_fingerprint` MUST be in this list: it is an always-serialised,
    // runtime-consumed anti-censorship control. Before it was added here the
    // pruner deleted a `pinned` profile on every save, silently reverting the
    // node to the default `rotate` policy (operator DPI-evasion downgrade).
    const KNOWN_SUB_TABLES: &[&str] = &["rotation", "tls_client", "tls_fingerprint"];
    let stale: Vec<String> = transport_table
        .iter()
        .filter_map(|(k, v)| {
            if v.is_table() && !KNOWN_SUB_TABLES.contains(&k) {
                Some(k.to_string())
            } else {
                None
            }
        })
        .collect();
    for k in stale {
        transport_table.remove(&k);
    }
    Ok(())
}

/// Always emit `[transport.rotation]` with the current `min`/`max`
/// pair, EVEN when it matches the baked-in default.  Rationale: see
/// `set_transport` — discoverability of the anti-DPI knob beats keeping
/// the file minimal.
fn set_rotation_table(table: &mut Table, rotation: &crate::TransportRotationConfig) -> Result<()> {
    if !table.get("rotation").is_some_and(Item::is_table) {
        table["rotation"] = Item::Table(Table::new());
    }
    let rotation_table =
        table["rotation"]
            .as_table_mut()
            .ok_or(ConfigError::TomlSectionNotTable {
                section: "transport.rotation",
            })?;
    rotation_table.insert(
        "min_lifetime_secs",
        Item::Value(Value::from(rotation.min_lifetime_secs)),
    );
    rotation_table.insert(
        "max_lifetime_secs",
        Item::Value(Value::from(rotation.max_lifetime_secs)),
    );
    Ok(())
}

/// Always emit `[transport.tls_fingerprint]` with the current policy, EVEN
/// when it matches the baked-in default.  Rationale mirrors
/// `set_rotation_table`: discoverability of the censor-evasion knob beats
/// keeping the file minimal, and the struct doc marks it "Always serialised".
fn set_tls_fingerprint_table(table: &mut Table, fp: &crate::TlsFingerprintConfig) -> Result<()> {
    if !table.get("tls_fingerprint").is_some_and(Item::is_table) {
        table["tls_fingerprint"] = Item::Table(Table::new());
    }
    let fp_table =
        table["tls_fingerprint"]
            .as_table_mut()
            .ok_or(ConfigError::TomlSectionNotTable {
                section: "transport.tls_fingerprint",
            })?;
    fp_table.insert("mode", Item::Value(Value::from(fp.mode.as_str())));
    fp_table.insert("profile", Item::Value(Value::from(fp.profile.as_str())));
    set_string_array(fp_table, "rotation", &fp.rotation);
    fp_table.insert("sticky", Item::Value(Value::from(fp.sticky)));
    Ok(())
}

fn set_tls_client_table(table: &mut Table, tls_client: &crate::TlsClientConfig) -> Result<()> {
    if tls_client.is_default() {
        table.remove("tls_client");
        return Ok(());
    }
    if !table.get("tls_client").is_some_and(Item::is_table) {
        table["tls_client"] = Item::Table(Table::new());
    }
    let tls_client_table =
        table["tls_client"]
            .as_table_mut()
            .ok_or(ConfigError::TomlSectionNotTable {
                section: "transport",
            })?;
    set_integer(
        tls_client_table,
        "connect_timeout_ms",
        checked_integer(
            "transport.tls_client.connect_timeout_ms",
            tls_client.connect_timeout_ms,
            u128::from,
        )?,
    );
    if tls_client_table.is_empty() {
        table.remove("tls_client");
    }
    Ok(())
}

fn set_ipc(document: &mut DocumentMut, ipc: &crate::IpcConfig) -> Result<()> {
    if ipc.is_default() {
        document.remove("ipc");
        return Ok(());
    }
    if !document.get("ipc").is_some_and(Item::is_table) {
        document["ipc"] = Item::Table(Table::new());
    }
    let ipc_table = document["ipc"]
        .as_table_mut()
        .ok_or(ConfigError::TomlSectionNotTable { section: "ipc" })?;
    match ipc_table.get_mut("enabled").and_then(Item::as_value_mut) {
        Some(existing) => replace_value(existing, Value::from(ipc.enabled)),
        None => {
            ipc_table["enabled"] = value(ipc.enabled);
        }
    }
    set_string_optional(ipc_table, "socket_uri", ipc.socket_uri.as_deref());
    set_string_optional(
        ipc_table,
        "app_socket_dir",
        ipc.app_socket_dir.as_deref().and_then(|p| p.to_str()),
    );
    Ok(())
}

fn set_peers(document: &mut DocumentMut, peers: &[crate::PeerConfig]) {
    // Render via serde so EVERY `PeerConfig` field is preserved on save. The
    // previous hand-maintained inline-table writer silently dropped `algo`
    // (audit cycle-9 CRIT-2) — a Falcon/hybrid peer reloaded as ed25519, failing
    // key-length/identity validation and becoming unreachable. The same
    // field-drift class previously dropped advertise/relay. Mirroring
    // `set_bootstrap_peers`'s serde render makes field coverage structural: a
    // new model field can no longer be forgotten here.
    document.remove("peers");
    if peers.is_empty() {
        return;
    }
    #[derive(serde::Serialize)]
    struct Wrapper<'a> {
        peers: &'a [crate::PeerConfig],
    }
    let rendered = toml::to_string_pretty(&Wrapper { peers }).unwrap_or_default();
    let sub: DocumentMut = rendered.parse().unwrap_or_default();
    if let Some(item) = sub.get("peers") {
        document["peers"] = item.clone();
    }
}

fn set_listens(document: &mut DocumentMut, listens: &[crate::ListenConfig]) {
    // Render via serde so EVERY `ListenConfig` field is preserved on save. The
    // previous hand-maintained inline-table writer dropped `visibility`,
    // `psk_file`, `allowlist_node_ids`, `group_label`, `ephemeral` and
    // `on_demand` (audit cycle-9 CRIT-1) — any save over an existing config
    // (incl. daemon-initiated peer-nonce persistence) silently turned a
    // stealth/hidden/trusted listener PUBLIC on the next load, binding the port
    // and announcing it in PEX/DHT (defeating PoW-gated rendezvous) and dropping
    // the allowlist accept-gate. The same drift earlier dropped advertise/relay.
    // Serde render makes field coverage structural — see `set_peers`.
    document.remove("listen");
    if listens.is_empty() {
        return;
    }
    #[derive(serde::Serialize)]
    struct Wrapper<'a> {
        listen: &'a [crate::ListenConfig],
    }
    let rendered = toml::to_string_pretty(&Wrapper { listen: listens }).unwrap_or_default();
    let sub: DocumentMut = rendered.parse().unwrap_or_default();
    if let Some(item) = sub.get("listen") {
        document["listen"] = item.clone();
    }
}

fn set_bootstrap_peers(document: &mut DocumentMut, peers: &[crate::BootstrapPeer]) {
    // Remove any existing [[bootstrap_peers]] array-of-tables.
    document.remove("bootstrap_peers");
    if peers.is_empty() {
        return;
    }
    // Serialize as an array-of-tables using toml::to_string_pretty on a
    // wrapper struct, then splice the resulting TOML into the document.
    // Because toml_edit has no ergonomic array-of-tables builder, we render
    // the bootstrap_peers sub-document and merge it in.
    #[derive(serde::Serialize)]
    struct Wrapper<'a> {
        bootstrap_peers: &'a [crate::BootstrapPeer],
    }
    let rendered = toml::to_string_pretty(&Wrapper {
        bootstrap_peers: peers,
    })
    .unwrap_or_default();
    let sub: DocumentMut = rendered.parse().unwrap_or_default();
    if let Some(item) = sub.get("bootstrap_peers") {
        document["bootstrap_peers"] = item.clone();
    }
}

fn set_metrics(document: &mut DocumentMut, metrics: Option<&crate::MetricsConfig>) {
    match metrics {
        Some(metrics) => {
            if !document.get("metrics").is_some_and(Item::is_table) {
                document["metrics"] = Item::Table(Table::new());
            }
            if let Some(metrics_table) = document["metrics"].as_table_mut() {
                set_string(metrics_table, "listen", &metrics.listen);
                set_string_optional(metrics_table, "path", metrics.path.as_deref());
                set_string_optional(metrics_table, "auth_token", metrics.auth_token.as_deref());
                if metrics.allow_unauthenticated_remote_metrics {
                    metrics_table["allow_unauthenticated_remote_metrics"] = value(true);
                } else {
                    metrics_table.remove("allow_unauthenticated_remote_metrics");
                }
            }
        }
        None => {
            document.remove("metrics");
        }
    }
}

fn checked_integer<T>(
    key: &'static str,
    value: Option<T>,
    to_u128: impl Fn(T) -> u128,
) -> Result<Option<i64>>
where
    T: TryInto<i64> + Copy,
{
    value
        .map(|value| {
            value
                .try_into()
                .map_err(|_| ConfigError::TomlIntegerOutOfRange {
                    key,
                    value: to_u128(value),
                })
        })
        .transpose()
}

fn replace_value(existing: &mut Value, mut replacement: Value) {
    std::mem::swap(existing.decor_mut(), replacement.decor_mut());
    *existing = replacement;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn updates_without_removing_comments() {
        let mut document = "[global]\n# for test\nruntime_flavor = \"multi_thread\"\n"
            .parse::<DocumentMut>()
            .unwrap();

        let mut config = Config::default();
        config.global.runtime_flavor = "current_thread".parse().unwrap();

        update_document(&mut document, &config).unwrap();

        let rendered = document.to_string();
        assert!(rendered.contains("# for test"));
        assert!(rendered.contains("runtime_flavor = \"current_thread\""));
    }

    #[test]
    fn adds_identity_section_when_missing() {
        let mut document = "[global]\nruntime_flavor = \"multi_thread\"\n"
            .parse::<DocumentMut>()
            .unwrap();

        let config = Config {
            identity: Some(crate::IdentityConfig {
                algo: crate::SignatureAlgorithm::Ed25519,
                role: Default::default(),
                public_key: "pub".to_owned(),
                private_key: "priv".to_owned(),
                nonce: "AAAAAA==".to_owned(),
                node_id: None,
                key_passphrase: None,
                key_passphrase_file: None,
                key_passphrase_prompt: false,
                lazy_mining: true,
                max_lazy_difficulty: 64,
            }),
            ..Config::default()
        };

        update_document(&mut document, &config).unwrap();

        let rendered = document.to_string();
        assert!(rendered.contains("[Identity]"));
        assert!(rendered.contains("algo = \"ed25519\""));
        assert!(rendered.contains("public_key = \"pub\""));
    }

    #[test]
    fn updates_existing_lowercase_identity_without_creating_uppercase_duplicate() {
        let mut document =
            "[global]\nruntime_flavor = \"multi_thread\"\n\n[identity]\nnonce = \"AAAAAA==\"\n"
                .parse::<DocumentMut>()
                .unwrap();

        let config = Config {
            identity: Some(crate::IdentityConfig {
                algo: crate::SignatureAlgorithm::Ed25519,
                role: Default::default(),
                public_key: "pub".to_owned(),
                private_key: "priv".to_owned(),
                nonce: "AQAAAA==".to_owned(),
                node_id: None,
                key_passphrase: None,
                key_passphrase_file: None,
                key_passphrase_prompt: false,
                lazy_mining: true,
                max_lazy_difficulty: 64,
            }),
            ..Config::default()
        };

        update_document(&mut document, &config).unwrap();

        let rendered = document.to_string();
        assert!(rendered.contains("[identity]"));
        assert!(!rendered.contains("[Identity]"));
        assert!(rendered.contains("public_key = \"pub\""));
        assert!(rendered.contains("private_key = \"priv\""));
        assert!(rendered.contains("nonce = \"AQAAAA==\""));
    }

    #[test]
    fn removing_identity_drops_uppercase_and_lowercase_sections() {
        let mut document = "[global]\nruntime_flavor = \"multi_thread\"\n\n[Identity]\npublic_key = \"upper\"\n\n[identity]\npublic_key = \"lower\"\n"
            .parse::<DocumentMut>()
            .unwrap();

        update_document(&mut document, &Config::default()).unwrap();

        let rendered = document.to_string();
        assert!(!rendered.contains("[Identity]"));
        assert!(!rendered.contains("[identity]"));
    }

    #[test]
    fn thread_keep_alive_ms_overflow_returns_error_without_removing_existing_key() {
        let mut document =
            "[global]\nthread_keep_alive_ms = 42\nruntime_flavor = \"multi_thread\"\n"
                .parse::<DocumentMut>()
                .unwrap();
        let mut config = Config::default();
        config.global.thread_keep_alive_ms = Some(u64::MAX);

        let err = update_document(&mut document, &config).unwrap_err();

        assert!(matches!(
            err,
            ConfigError::TomlIntegerOutOfRange {
                key: "global.thread_keep_alive_ms",
                value,
            } if value == u128::from(u64::MAX)
        ));
        assert!(document.to_string().contains("thread_keep_alive_ms = 42"));
    }

    #[test]
    fn thread_stack_size_overflow_returns_error_without_removing_existing_key() {
        let mut document = "[global]\nthread_stack_size = 64\nruntime_flavor = \"multi_thread\"\n"
            .parse::<DocumentMut>()
            .unwrap();
        let mut config = Config::default();
        config.global.thread_stack_size = Some(usize::MAX);

        let err = update_document(&mut document, &config).unwrap_err();

        assert!(matches!(
            err,
            ConfigError::TomlIntegerOutOfRange {
                key: "global.thread_stack_size",
                value,
            } if value == (usize::MAX as u128)
        ));
        assert!(document.to_string().contains("thread_stack_size = 64"));
    }

    #[test]
    fn adds_node_sections_when_missing() {
        let mut document = "[global]\nruntime_flavor = \"multi_thread\"\n"
            .parse::<DocumentMut>()
            .unwrap();
        let mut config = Config::default();
        config.global.admin_socket = Some("unix:///tmp/veil.sock".to_owned());
        config.global.logs = crate::LogsConfig::File;
        config.global.log_file = Some("/tmp/veil.log".to_owned());
        config.peers.push(crate::PeerConfig {
            peer_id: crate::PeerId::new(1),
            public_key: "pub".to_owned(),
            nonce: "AAAAAA==".to_owned(),
            transport: "tcp://127.0.0.1:9000".to_owned(),
            algo: Default::default(),
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            alt_uri: None,
        });
        config.listen.push(crate::ListenConfig {
            id: crate::ListenId::new(2),
            transport: "tcp://127.0.0.1:9001".to_owned(),
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            advertise: None,
            relay: None,
            ..Default::default()
        });
        config.metrics = Some(crate::MetricsConfig {
            listen: "tcp://127.0.0.1:9100".to_owned(),
            path: Some("/metrics".to_owned()),
            auth_token: None,
            allow_unauthenticated_remote_metrics: false,
        });

        update_document(&mut document, &config).unwrap();

        let rendered = document.to_string();
        assert!(rendered.contains("admin_socket = \"unix:///tmp/veil.sock\""));
        assert!(rendered.contains("logs = \"file\""));
        assert!(rendered.contains("[metrics]"));
        // peers/listen now render as array-of-tables via serde (cycle-9 CRIT-1/2
        // field-preservation fix) rather than inline `peers = [{...}]`.
        assert!(rendered.contains("[[peers]]"), "rendered: {rendered}");
        assert!(rendered.contains("[[listen]]"), "rendered: {rendered}");
        // Round-trips with all fields intact.
        let reloaded = load_config(&rendered).expect("re-parses");
        assert_eq!(reloaded.peers.len(), 1);
        assert_eq!(reloaded.listen.len(), 1);
    }

    #[test]
    fn cycle9_listen_and_peer_save_preserves_all_fields() {
        // audit cycle-9 CRIT-1/CRIT-2: a save over an EXISTING config (incl. a
        // daemon-initiated peer-nonce persist) must not drop listener
        // visibility/allowlist/psk/group/ephemeral/on_demand (silent
        // stealth→public downgrade) or peer `algo` (Falcon→ed25519 downgrade).
        // This also re-parses the patched output, catching any array-of-tables
        // placement corruption from the serde-render path.
        let existing = "[global]\nruntime_flavor = \"multi_thread\"\n\
             listen = [{ id = \"2\", transport = \"tcp://127.0.0.1:9001\" }]\n\
             [identity]\nnonce = \"AAAAAA==\"\n";
        let mut document = existing.parse::<DocumentMut>().unwrap();

        let mut config = Config::default();
        config.listen.push(crate::ListenConfig {
            id: crate::ListenId::new(2),
            transport: "tcp://127.0.0.1:9001".to_owned(),
            visibility: crate::Visibility::Stealth,
            group_label: Some("friends".to_owned()),
            psk_file: Some(std::path::PathBuf::from("/etc/veil/psk")),
            allowlist_node_ids: vec!["aa".to_owned(), "bb".to_owned()],
            ..Default::default()
        });
        config.peers.push(crate::PeerConfig {
            peer_id: crate::PeerId::new(1),
            public_key: "pub".to_owned(),
            nonce: "AAAAAA==".to_owned(),
            transport: "tcp://127.0.0.1:9000".to_owned(),
            algo: crate::SignatureAlgorithm::Falcon512,
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            alt_uri: None,
        });

        update_document(&mut document, &config).unwrap();
        let rendered = document.to_string();

        // Re-parse the patched TOML (fails if array-of-tables placement broke it).
        let reloaded = load_config(&rendered).expect("patched config must re-parse");
        let l = &reloaded.listen[0];
        assert_eq!(
            l.visibility,
            crate::Visibility::Stealth,
            "visibility must survive save (CRIT-1)"
        );
        assert_eq!(l.allowlist_node_ids, vec!["aa".to_owned(), "bb".to_owned()]);
        assert_eq!(l.group_label.as_deref(), Some("friends"));
        assert_eq!(
            l.psk_file.as_deref(),
            Some(std::path::Path::new("/etc/veil/psk"))
        );
        assert_eq!(
            reloaded.peers[0].algo,
            crate::SignatureAlgorithm::Falcon512,
            "peer algo must survive save (CRIT-2)"
        );
    }

    #[test]
    fn adds_ipc_section_when_enabled() {
        let mut document = "[global]\nruntime_flavor = \"multi_thread\"\n"
            .parse::<DocumentMut>()
            .unwrap();

        let config = Config {
            ipc: crate::IpcConfig {
                enabled: true,
                ..Default::default()
            },
            ..Config::default()
        };

        update_document(&mut document, &config).unwrap();

        let rendered = document.to_string();
        assert!(rendered.contains("[ipc]"), "rendered: {rendered}");
        assert!(rendered.contains("enabled = true"), "rendered: {rendered}");
    }

    #[test]
    fn removes_ipc_section_when_disabled() {
        let mut document = "[global]\nruntime_flavor = \"multi_thread\"\n\n[ipc]\nenabled = true\n"
            .parse::<DocumentMut>()
            .unwrap();

        update_document(&mut document, &Config::default()).unwrap();

        let rendered = document.to_string();
        assert!(!rendered.contains("[ipc]"), "rendered: {rendered}");
    }

    #[test]
    fn removes_default_transport_sections() {
        let mut document = "[transport]\n[transport.tls_client]\nbrowser_profile = \"chrome_like\"\n[transport.quic_client]\nbackend = \"native_quinn\"\n[transport.websocket]\n"
            .parse::<DocumentMut>()
            .unwrap();

        update_document(&mut document, &Config::default()).unwrap();

        let rendered = document.to_string();
        // [transport] and [transport.rotation] are now ALWAYS emitted
        // (rotation is a discoverable anti-DPI knob — see set_transport).
        // Other default sub-tables still get removed.
        assert!(rendered.contains("[transport.rotation]"));
        assert!(!rendered.contains("[transport.tls_client]"));
        assert!(!rendered.contains("[transport.quic_client]"));
        assert!(!rendered.contains("[transport.websocket]"));
        assert!(!rendered.contains("browser_profile"));
    }

    #[test]
    fn rotation_section_always_emitted_with_defaults() {
        // Fresh config (no existing [transport] in document) must
        // still get a [transport.rotation] section with default values.
        let mut document = DocumentMut::new();
        update_document(&mut document, &Config::default()).unwrap();
        let rendered = document.to_string();
        assert!(
            rendered.contains("[transport.rotation]"),
            "rotation section must always appear, got: {rendered}"
        );
        assert!(rendered.contains("min_lifetime_secs = 1800"));
        assert!(rendered.contains("max_lifetime_secs = 3600"));
    }

    #[test]
    fn rotation_section_reflects_custom_values() {
        let mut config = Config::default();
        config.transport.rotation.min_lifetime_secs = 600;
        config.transport.rotation.max_lifetime_secs = 1_200;
        let mut document = DocumentMut::new();
        update_document(&mut document, &config).unwrap();
        let rendered = document.to_string();
        assert!(rendered.contains("min_lifetime_secs = 600"));
        assert!(rendered.contains("max_lifetime_secs = 1200"));
    }

    #[test]
    fn rotation_section_emits_minus_one_disable_sentinel() {
        let mut config = Config::default();
        config.transport.rotation.min_lifetime_secs = -1;
        config.transport.rotation.max_lifetime_secs = -1;
        let mut document = DocumentMut::new();
        update_document(&mut document, &config).unwrap();
        let rendered = document.to_string();
        assert!(rendered.contains("min_lifetime_secs = -1"));
        assert!(rendered.contains("max_lifetime_secs = -1"));
    }

    #[test]
    fn tls_fingerprint_pinned_survives_save() {
        // Regression: the [transport.*] pruner used to delete the live,
        // runtime-consumed `tls_fingerprint` section on every save, silently
        // reverting a pinned anti-DPI profile to the default `rotate` policy.
        let mut document =
            "[transport]\n[transport.tls_fingerprint]\nmode = \"pinned\"\nprofile = \"firefox\"\n"
                .parse::<DocumentMut>()
                .unwrap();
        let mut config = Config::default();
        config.transport.tls_fingerprint.mode = "pinned".to_owned();
        config.transport.tls_fingerprint.profile = "firefox".to_owned();

        update_document(&mut document, &config).unwrap();

        let rendered = document.to_string();
        assert!(
            rendered.contains("[transport.tls_fingerprint]"),
            "tls_fingerprint section must survive a save, got: {rendered}"
        );
        assert!(rendered.contains("mode = \"pinned\""));
        assert!(rendered.contains("profile = \"firefox\""));
    }

    #[test]
    fn tls_fingerprint_section_always_emitted_with_defaults() {
        let mut document = DocumentMut::new();
        update_document(&mut document, &Config::default()).unwrap();
        let rendered = document.to_string();
        assert!(
            rendered.contains("[transport.tls_fingerprint]"),
            "tls_fingerprint section must always appear, got: {rendered}"
        );
        assert!(rendered.contains("mode = \"rotate\""));
    }
}
