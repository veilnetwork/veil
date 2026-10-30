//! Scoped opaque-cell correlation, compiled out unless `circuit-trace` is on.
//!
//! An operator supplies `VEIL_CIRCUIT_TRACE_FILE`, a private regular file:
//! ```text
//! key <64 hex digits, fresh random key shared by the investigation nodes>
//! local
//! prefix <32 hex digits, keyed prefix token printed by the selected endpoint>
//! peer <64 hex digits, explicitly selected adjacent transport peer>
//! ```
//! `local` is for the controlled endpoint only. Relays use only `prefix` and
//! `peer`: opaque prefix matching at a splice, or a selected adjacent link.
//! Prefixes are NOT decoded as identities, stream frames or media. A key alone
//! enables nothing. No payload, cookie, key or peer address is printed here.
//!
//! Filters may be updated without restarting a circuit (refresh <= 1 s), but
//! neither edits nor a key change renew the process's 10 minute / 32768 event
//! budget. A missing, oversized, public, symlinked or malformed file disables
//! observation. File activation is supported on Unix only (no Windows ACL
//! verifier here). This is private operator evidence, NOT an anonymous report:
//! within one key's lifetime it intentionally permits cell correlation.

/// Only short, keyed, investigation-local tokens; never payload or key bytes.
pub struct Observation {
    pub event: u64,
    pub token: String,
    pub prefix: String,
}

/// Observe an opaque cell created by this process, excluding its target cookie.
#[inline]
pub fn local(opaque: &[u8]) -> Option<Observation> {
    observe(opaque, None, true)
}

/// Observe only an explicitly selected opaque prefix at a splice/endpoint.
#[inline]
pub fn selected(opaque: &[u8]) -> Option<Observation> {
    observe(opaque, None, false)
}

/// Observe only the explicitly selected adjacent transport peer. Does not
/// inspect the cell's contents or expose the peer identifier in its result.
#[inline]
pub fn peer(peer: &[u8; 32]) -> Option<Observation> {
    observe(&[], Some(peer), false)
}

#[cfg(not(feature = "circuit-trace"))]
#[inline]
fn observe(_: &[u8], _: Option<&[u8; 32]>, _: bool) -> Option<Observation> {
    None
}

#[cfg(feature = "circuit-trace")]
fn observe(opaque: &[u8], peer: Option<&[u8; 32]>, local: bool) -> Option<Observation> {
    use std::sync::{Mutex, OnceLock};
    use std::time::Instant;
    static STATE: OnceLock<Option<Mutex<enabled::State>>> = OnceLock::new();
    let state = STATE.get_or_init(|| {
        std::env::var_os("VEIL_CIRCUIT_TRACE_FILE")
            .filter(|p| !p.is_empty())
            .map(|p| Mutex::new(enabled::State::new(p.into(), Instant::now())))
    });
    let mut state = state.as_ref()?.lock().ok()?;
    state.observe(opaque, peer, local, Instant::now())
}

#[cfg(feature = "circuit-trace")]
mod enabled {
    use super::Observation;
    #[cfg(unix)]
    use std::io::Read;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};
    use zeroize::{Zeroize, Zeroizing};

    const LEASE: Duration = Duration::from_secs(600);
    const REFRESH: Duration = Duration::from_secs(1);
    const MAX_EVENTS: u64 = 32768;
    #[cfg(unix)]
    const MAX_FILE_BYTES: u64 = 4096;
    const MAX_FILTERS: usize = 16;

    #[derive(Default)]
    struct Policy {
        key: Zeroizing<[u8; 32]>,
        local: bool,
        prefixes: Vec<[u8; 16]>,
        peers: Vec<[u8; 32]>,
    }

    #[cfg(any(unix, test))]
    fn hex<const N: usize>(s: &str) -> Option<[u8; N]> {
        if s.len() != N * 2 {
            return None;
        }
        let mut out = [0; N];
        for (byte, pair) in out.iter_mut().zip(s.as_bytes().chunks_exact(2)) {
            let digit = |c: u8| match c {
                b'0'..=b'9' => Some(c - b'0'),
                b'a'..=b'f' => Some(c - b'a' + 10),
                b'A'..=b'F' => Some(c - b'A' + 10),
                _ => None,
            };
            *byte = digit(pair[0])? * 16 + digit(pair[1])?;
        }
        Some(out)
    }

    fn token(key: &[u8; 32], domain: &[u8], bytes: &[u8]) -> [u8; 16] {
        let mut hash = blake3::Hasher::new_keyed(key);
        hash.update(domain);
        hash.update(bytes);
        hash.finalize().as_bytes()[..16].try_into().unwrap()
    }

    fn show(bytes: &[u8; 16]) -> String {
        veil_util::hex_str(bytes)
    }

    impl Policy {
        #[cfg(any(unix, test))]
        fn parse(text: &str) -> Option<Self> {
            let mut policy = Self::default();
            let mut key_seen = false;
            for line in text.lines() {
                let parts: Vec<_> = line.split_whitespace().collect();
                match parts.as_slice() {
                    [] => {}
                    ["key", value] if !key_seen => {
                        *policy.key = hex(value)?;
                        key_seen = true;
                    }
                    ["local"] if !policy.local => policy.local = true,
                    ["prefix", value] if policy.prefixes.len() < MAX_FILTERS => {
                        policy.prefixes.push(hex(value)?);
                    }
                    ["peer", value] if policy.peers.len() < MAX_FILTERS => {
                        policy.peers.push(hex(value)?);
                    }
                    _ => return None,
                }
            }
            key_seen.then_some(policy)
        }

        #[cfg(not(unix))]
        fn load(_: &Path) -> Option<Self> {
            None // no ACL verifier here; ordinary Windows diagnostics are separate
        }

        #[cfg(unix)]
        fn load(path: &Path) -> Option<Self> {
            let metadata = std::fs::symlink_metadata(path).ok()?;
            if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
                return None;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return None;
                }
            }
            let file = std::fs::File::open(path).ok()?;
            // Re-check the opened file, not just the path (operator may replace
            // a filter file atomically while this node is running).
            let opened = file.metadata().ok()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                if metadata.dev() != opened.dev()
                    || metadata.ino() != opened.ino()
                    || opened.permissions().mode() & 0o077 != 0
                {
                    return None;
                }
            }
            if !opened.is_file() {
                return None;
            }
            let mut text = Zeroizing::new(String::new());
            file.take(MAX_FILE_BYTES + 1)
                .read_to_string(&mut text)
                .ok()?;
            if text.len() as u64 > MAX_FILE_BYTES {
                return None;
            }
            Self::parse(&text)
        }
    }

    pub(super) struct State {
        path: PathBuf,
        started: Instant,
        refreshed: Option<Instant>,
        policy: Option<Policy>,
        events: u64,
    }

    impl State {
        pub(super) fn new(path: PathBuf, now: Instant) -> Self {
            Self {
                path,
                started: now,
                refreshed: None,
                policy: None,
                events: 0,
            }
        }

        pub(super) fn observe(
            &mut self,
            opaque: &[u8],
            peer: Option<&[u8; 32]>,
            local: bool,
            now: Instant,
        ) -> Option<Observation> {
            if now.saturating_duration_since(self.started) >= LEASE || self.events >= MAX_EVENTS {
                self.policy = None; // also scrub the key after the hard limit
                return None;
            }
            if self
                .refreshed
                .is_none_or(|last| now.saturating_duration_since(last) >= REFRESH)
            {
                self.policy = Policy::load(&self.path);
                self.refreshed = Some(now);
            }
            let policy = self.policy.as_ref()?;
            let prefix = (opaque.len() >= 32)
                .then(|| token(&policy.key, b"veil-circuit-prefix-v1", &opaque[..32]));
            let allowed = match peer {
                Some(peer) => policy.peers.contains(peer),
                None if local => policy.local,
                None => prefix.is_some_and(|p| policy.prefixes.contains(&p)),
            };
            if !allowed {
                return None;
            }
            self.events += 1;
            Some(Observation {
                event: self.events,
                token: match peer {
                    None => show(&token(&policy.key, b"veil-circuit-cell-v1", opaque)),
                    Some(peer) => show(&token(&policy.key, b"veil-circuit-peer-v1", peer)),
                },
                prefix: prefix.map(|p| show(&p)).unwrap_or_default(),
            })
        }
    }

    impl Drop for Policy {
        fn drop(&mut self) {
            self.peers.zeroize();
            self.prefixes.zeroize();
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn selection_is_explicit_and_tokens_are_keyed_and_domain_separated() {
            let key = [7; 32];
            let opaque = [42; 120];
            let prefix = token(&key, b"veil-circuit-prefix-v1", &opaque[..32]);
            let cell = token(&key, b"veil-circuit-cell-v1", &opaque);
            assert_ne!(prefix, cell);
            assert_ne!(cell, token(&[8; 32], b"veil-circuit-cell-v1", &opaque));
            let policy = Policy::parse(&format!(
                "key {}\nprefix {}\npeer {}",
                veil_util::hex_str(&key),
                show(&prefix),
                "05".repeat(32)
            ))
            .unwrap();
            assert!(!policy.local);
            assert_eq!(policy.prefixes, vec![prefix]);
            assert_eq!(policy.peers, vec![[5; 32]]);
            assert!(Policy::parse(&format!("key {}\nall", "07".repeat(32))).is_none());
            assert!(
                Policy::parse(&format!("key {}\nkey {}", "07".repeat(32), "08".repeat(32)))
                    .is_none()
            );
        }

        #[test]
        fn oversized_or_invalid_filters_fail_closed() {
            let key = format!("key {}\n", "07".repeat(32));
            assert!(
                Policy::parse(&(key.clone() + &format!("prefix {}\n", "01".repeat(16)).repeat(17)))
                    .is_none()
            );
            assert!(Policy::parse(&(key + "peer xyz")).is_none());
            assert!(Policy::parse("local").is_none());
        }

        #[cfg(unix)]
        #[test]
        fn public_symlinked_oversized_and_key_only_files_do_not_enable_capture() {
            use rand_core::RngCore;
            use std::io::Write;
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
            let dir = std::env::temp_dir().join(format!(
                "veil-circuit-policy-{:016x}",
                rand_core::OsRng.next_u64()
            ));
            std::fs::create_dir(&dir).unwrap();
            let path = dir.join("policy");
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            writeln!(file, "key {}", "07".repeat(32)).unwrap();
            let now = Instant::now();
            let mut state = State::new(path.clone(), now);
            assert!(state.observe(&[42; 100], None, true, now).is_none());
            assert!(state.observe(&[42; 100], None, false, now).is_none());
            assert!(state.observe(&[], Some(&[5; 32]), false, now).is_none());
            assert_eq!(state.events, 0);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(Policy::load(&path).is_none());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let link = dir.join("link");
            symlink(&path, &link).unwrap();
            assert!(Policy::load(&link).is_none());
            file.set_len(MAX_FILE_BYTES + 1).unwrap();
            assert!(Policy::load(&path).is_none());
            std::fs::remove_dir_all(dir).unwrap();
        }

        #[cfg(unix)]
        #[test]
        fn updates_do_not_renew_lease_or_budget_and_removal_disables_observation() {
            use rand_core::RngCore;
            let path = std::env::temp_dir().join(format!(
                "veil-circuit-trace-{:016x}",
                rand_core::OsRng.next_u64()
            ));
            let write = |text: &str| {
                use std::fs::OpenOptions;
                use std::io::Write;
                let mut options = OpenOptions::new();
                options.write(true).create(true).truncate(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                options
                    .open(&path)
                    .unwrap()
                    .write_all(text.as_bytes())
                    .unwrap();
            };
            write(&format!("key {}\nlocal", "07".repeat(32)));
            let now = Instant::now();
            let mut state = State::new(path.clone(), now);
            let opaque = [42; 100];
            assert!(state.observe(&opaque, None, true, now).is_some());
            assert!(state.observe(&opaque, None, false, now).is_none());
            assert!(state.observe(&[], Some(&[5; 32]), false, now).is_none());
            let prefix = show(&token(&[7; 32], b"veil-circuit-prefix-v1", &opaque[..32]));
            write(&format!(
                "key {}\nprefix {prefix}\npeer {}",
                "07".repeat(32),
                "05".repeat(32)
            ));
            assert!(state.observe(&opaque, None, false, now + REFRESH).is_some());
            assert!(
                state
                    .observe(&[], Some(&[5; 32]), false, now + REFRESH)
                    .is_some()
            );
            std::fs::remove_file(&path).unwrap();
            assert!(
                state
                    .observe(&opaque, None, false, now + REFRESH * 2)
                    .is_none()
            );
            write(&format!("key {}\nlocal", "08".repeat(32)));
            state.events = MAX_EVENTS;
            assert!(
                state
                    .observe(&opaque, None, true, now + REFRESH * 3)
                    .is_none()
            );
            state.events = 0;
            assert!(state.observe(&opaque, None, true, now + LEASE).is_none());
            std::fs::remove_file(&path).unwrap();
        }
    }
}

#[cfg(all(test, not(feature = "circuit-trace")))]
mod disabled_tests {
    #[test]
    fn ordinary_build_cannot_observe_cells() {
        assert!(super::local(&[42; 100]).is_none());
        assert!(super::selected(&[42; 100]).is_none());
        assert!(super::peer(&[5; 32]).is_none());
    }
}
