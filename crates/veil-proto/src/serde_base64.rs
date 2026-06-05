//! Base64-string serde helpers for byte arrays.
//!
//! Moved here from `node::dht::kademlia` so wire-format definitions
//! in `proto::*` can reference them without crossing the proto → node
//! dependency direction (cycle blocker for crate extraction).
//!
//! Used by `proto/discovery.rs`, `node/dht/kademlia.rs` (DHT snapshot
//! JSON), and any future proto type that wants base64-encoded byte
//! fields in its serde representation.

/// Serde helper: encode `[u8; 32]` as a base64 string.
pub mod hex_array {
    use base64::Engine as _;
    use serde::{Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = <&str as serde::Deserialize>::deserialize(d)?;
        let v = base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(D::Error::custom)?;
        v.try_into()
            .map_err(|_| D::Error::custom("expected 32 bytes"))
    }
}

/// Serde helper: encode `Vec<u8>` as a base64 string.
pub mod serde_bytes_base64 {
    use base64::Engine as _;
    use serde::{Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = <&str as serde::Deserialize>::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(D::Error::custom)
    }
}
