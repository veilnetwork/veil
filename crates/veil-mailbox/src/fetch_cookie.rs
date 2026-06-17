//! Private, per-relay, per-epoch mailbox **fetch** cookie.
//!
//! ## Why this exists (security)
//!
//! Mailbox `fetch`/`ack` are authenticated to a relay by a 16-byte cookie. The
//! onion rendezvous cookie is *published* in the receiver's `RendezvousAd`
//! (it's a shared secret the receiver hands to senders for `ForwardIntroduce`),
//! so if the mailbox reused it, **any contact who resolved the ad could drain
//! the receiver's mailbox**. To close that, the mailbox fetch cookie is a
//! SEPARATE secret: derived from a stable identity secret, registered with the
//! relay, and NEVER placed in a resolvable ad. The ad carries only the
//! `capability_token` (sender-facing, gates `put`).
//!
//! ## Properties
//!
//! - **Deterministic + stateless**: re-derivable after a restart, so blobs
//!   deposited while the receiver was offline stay fetchable. No persisted
//!   cookie to lose.
//! - **Per-relay** (`relay_id` bound): different relays see different cookies,
//!   so colluding relays can't cross-correlate the receiver by cookie.
//! - **Per-epoch** (`epoch` bound): rotates over time, bounding the lifetime of
//!   a leaked cookie and the correlation window at a single relay. The receiver
//!   re-registers the freshly-derived cookie each epoch; the relay should accept
//!   the current AND previous epoch so a fetch straddling the boundary survives.

/// Wire length of a mailbox auth cookie (matches `auth_cookie: [u8; 16]`).
pub const MAILBOX_COOKIE_LEN: usize = 16;

/// Epoch length for fetch-cookie rotation. 1 hour: a leaked cookie expires
/// within ≤2 epochs (current+previous accepted), and re-registration is cheap
/// (~24/day). Tunable — longer trades rotation for fewer re-registrations.
pub const MAILBOX_COOKIE_EPOCH_SECS: u64 = 3600;

/// BLAKE3 KDF domain. Unique to this purpose so the derived cookie can never
/// collide with another key derived from the same identity secret.
const COOKIE_CONTEXT: &str = "veil.mailbox.fetch-cookie.v1";

/// The cookie epoch for `now_unix_secs`.
#[must_use]
pub fn mailbox_cookie_epoch(now_unix_secs: u64) -> u64 {
    now_unix_secs / MAILBOX_COOKIE_EPOCH_SECS
}

/// Derive the private mailbox fetch cookie for (`identity_secret`, `relay_id`,
/// `epoch`). See the module docs for the security rationale. `identity_secret`
/// should be a STABLE secret of the identity (e.g. its master/identity key
/// material) so the cookie is consistent across the identity's lifetime.
#[must_use]
pub fn derive_mailbox_fetch_cookie(
    identity_secret: &[u8],
    relay_id: &[u8; 32],
    epoch: u64,
) -> [u8; MAILBOX_COOKIE_LEN] {
    // Key material binds relay_id + epoch + the secret; the domain-separated
    // BLAKE3 KDF context prevents cross-protocol reuse.
    let mut ikm = Vec::with_capacity(32 + 8 + identity_secret.len());
    ikm.extend_from_slice(relay_id);
    ikm.extend_from_slice(&epoch.to_be_bytes());
    ikm.extend_from_slice(identity_secret);
    let full = blake3::derive_key(COOKIE_CONTEXT, &ikm);
    let mut cookie = [0u8; MAILBOX_COOKIE_LEN];
    cookie.copy_from_slice(&full[..MAILBOX_COOKIE_LEN]);
    cookie
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"a stable identity secret, >=32 bytes long here";
    const RELAY_A: [u8; 32] = [0xA1; 32];
    const RELAY_B: [u8; 32] = [0xB2; 32];

    #[test]
    fn deterministic_for_same_inputs() {
        let a = derive_mailbox_fetch_cookie(SECRET, &RELAY_A, 100);
        let b = derive_mailbox_fetch_cookie(SECRET, &RELAY_A, 100);
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_per_relay() {
        let a = derive_mailbox_fetch_cookie(SECRET, &RELAY_A, 100);
        let b = derive_mailbox_fetch_cookie(SECRET, &RELAY_B, 100);
        assert_ne!(a, b, "different relays must not share a cookie");
    }

    #[test]
    fn distinct_per_epoch() {
        let a = derive_mailbox_fetch_cookie(SECRET, &RELAY_A, 100);
        let b = derive_mailbox_fetch_cookie(SECRET, &RELAY_A, 101);
        assert_ne!(a, b, "cookie must rotate across epochs");
    }

    #[test]
    fn distinct_per_secret() {
        let a = derive_mailbox_fetch_cookie(SECRET, &RELAY_A, 100);
        let b = derive_mailbox_fetch_cookie(b"a DIFFERENT identity secret entirely!!", &RELAY_A, 100);
        assert_ne!(a, b, "different identities must not share a cookie");
    }

    #[test]
    fn not_trivially_weak() {
        let c = derive_mailbox_fetch_cookie(SECRET, &RELAY_A, 100);
        assert_ne!(c, [0u8; MAILBOX_COOKIE_LEN], "cookie must not be all-zero");
    }

    #[test]
    fn epoch_boundary() {
        assert_eq!(mailbox_cookie_epoch(0), 0);
        assert_eq!(mailbox_cookie_epoch(MAILBOX_COOKIE_EPOCH_SECS - 1), 0);
        assert_eq!(mailbox_cookie_epoch(MAILBOX_COOKIE_EPOCH_SECS), 1);
        assert_eq!(mailbox_cookie_epoch(MAILBOX_COOKIE_EPOCH_SECS * 5 + 9), 5);
    }
}
