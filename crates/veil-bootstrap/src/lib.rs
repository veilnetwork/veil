//! Bootstrap autoconfiguration.
//!
//! Provides fallback peer discovery when `config.peers` and
//! `config.bootstrap_peers` are both empty:
//!
//! 1. **Builtin seeds** — compile-time seed list embedded in the binary.
//! 2. **DNS discovery** — queries `_veil._bootstrap.<domain>` TXT records.
//! 3. **Runtime rotation** — (future) DHT-based seed set updates with TOFU policy.

pub mod cache;
pub mod dns;
pub mod encrypted_invite;
pub mod https;
pub mod invite;
pub mod seeds;
pub mod signed_bundle;
pub mod signed_invite;

pub use cache::{
    DiscoveredPeer, DiscoveredPeerCache, MAX_DISCOVERED_PEERS, load_or_generate_cache_hmac_key,
};
pub use dns::discover_seeds_dns;
pub use encrypted_invite::{
    ENCRYPTED_INVITE_SCHEME, EncryptedInviteError, MAX_ENCRYPTED_INVITE_BYTES, decrypt_invite,
    encrypt_invite,
};
pub use https::{
    DEFAULT_BINARY_FETCH_TIMEOUT, DEFAULT_CHUNK_READ_TIMEOUT, HttpsBootstrapError,
    MAX_RESPONSE_BYTES as MAX_HTTPS_RESPONSE_BYTES, fetch_binary_bytes_https, fetch_bytes_https,
    fetch_seeds_https,
};
pub use invite::{
    BOOTSTRAP_URI_SCHEME, BootstrapUriError, MAX_BOOTSTRAP_URI_BYTES,
    decode_uri as decode_bootstrap_uri, encode_uri as encode_bootstrap_uri,
};
pub use seeds::{
    bootstrap_bundle_dht_key, builtin_seeds, decode_bootstrap_bundle, encode_bootstrap_bundle,
};
pub use signed_bundle::{
    MAX_BUNDLE_AGE_SECS, MAX_SIGNED_BUNDLE_BYTES, SIGNED_BUNDLE_MAGIC, SignedBootstrapBundle,
    SignedBundleError, decode_signed_bundle, sign_bundle, verify_signed_bundle,
};
pub use signed_invite::{
    MAX_SIGNED_INVITE_BYTES, SIGNED_INVITE_SCHEME, SignedInvite, SignedInviteError,
    decode_signed_invite, sign_invite, verify_signed_invite,
};
