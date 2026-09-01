//! NIP-01 events: what a relay will accept, and what it will not.
//!
//! The id is a SHA-256 over a JSON array with no whitespace, and the signature
//! is BIP-340 schnorr over that id. Both are checked by every relay before it
//! stores anything, so an implementation that is nearly right is an
//! implementation whose events are silently dropped.

use k256::schnorr::signature::hazmat::{PrehashSigner as _, PrehashVerifier as _};
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// NIP-78: "application-specific data", addressable per `d` tag.
///
/// Chosen rather than a number picked out of the air: the kind range
/// 30000-39999 is addressable, meaning a relay keeps only the LATEST event per
/// (pubkey, kind, `d`) — which is exactly the shape of "here is where I am
/// now", and means a node's announcement replaces itself instead of piling up.
pub const KIND_APP_DATA: u16 = 30078;

/// A signed event, in the field order NIP-01 shows.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: i64,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

/// Why an event was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventError {
    /// The id is not the hash of the rest of the event. Either the event was
    /// altered in flight or the sender computes it differently, and both mean
    /// the same thing here: do not act on it.
    IdMismatch,
    /// The signature does not verify against the pubkey.
    BadSignature,
    /// A hex field that is not hex, or not the right length.
    Malformed,
}

impl std::fmt::Display for EventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::IdMismatch => "id is not the hash of the event",
            Self::BadSignature => "signature does not verify",
            Self::Malformed => "malformed hex field",
        })
    }
}

impl std::error::Error for EventError {}

/// The exact bytes NIP-01 hashes to get the id.
///
/// `[0, pubkey, created_at, kind, tags, content]`, serialised with no
/// whitespace. `serde_json` produces precisely this: it emits raw UTF-8 rather
/// than `\u` escapes, and escapes the control characters the way NIP-01 asks.
/// Anything else here and every relay drops every event this node sends.
pub fn serialize_for_id(
    pubkey_hex: &str,
    created_at: i64,
    kind: u16,
    tags: &[Vec<String>],
    content: &str,
) -> String {
    serde_json::json!([0, pubkey_hex, created_at, kind, tags, content]).to_string()
}

/// The id of an unsigned event.
pub fn event_id(
    pubkey_hex: &str,
    created_at: i64,
    kind: u16,
    tags: &[Vec<String>],
    content: &str,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(serialize_for_id(pubkey_hex, created_at, kind, tags, content).as_bytes());
    h.finalize().into()
}

/// Build and sign one event.
pub fn sign(
    key: &SigningKey,
    created_at: i64,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: &str,
) -> Event {
    let pubkey = hex_lower(&key.verifying_key().to_bytes());
    let id = event_id(&pubkey, created_at, kind, &tags, content);
    // PREHASH, not `sign`. `k256`'s `Signer::sign` hashes the message with
    // SHA-256 first; Nostr signs the id RAW, because the id already is a
    // SHA-256 and BIP-340 takes it as the message. Signing `sha256(id)`
    // produces a signature this code verifies happily and every relay rejects
    // with "invalid: bad signature" — which is what two of them said.
    let sig: Signature = key
        .sign_prehash(&id)
        .expect("a 32-byte prehash is signable");
    Event {
        id: hex_lower(&id),
        pubkey,
        created_at,
        kind,
        tags,
        content: content.to_owned(),
        sig: hex_lower(&sig.to_bytes()),
    }
}

/// Check an event the way a relay does, and then some.
///
/// Both halves, in this order. Verifying the signature without recomputing the
/// id would accept an event whose CONTENT had been swapped for another with a
/// valid signature over a different id — the signature is over the id, and the
/// id is the only thing binding it to the content.
pub fn verify(event: &Event) -> Result<(), EventError> {
    let id = event_id(
        &event.pubkey,
        event.created_at,
        event.kind,
        &event.tags,
        &event.content,
    );
    if hex_lower(&id) != event.id {
        return Err(EventError::IdMismatch);
    }
    let pubkey = unhex(&event.pubkey).ok_or(EventError::Malformed)?;
    if pubkey.len() != 32 {
        return Err(EventError::Malformed);
    }
    let verifying = VerifyingKey::from_bytes(&pubkey).map_err(|_| EventError::Malformed)?;
    let raw = unhex(&event.sig).ok_or(EventError::Malformed)?;
    // Length FIRST. `k256` 0.13.4 panics inside `Signature::try_from` on a
    // slice shorter than 64 bytes (`mid > len`), and this slice comes from a
    // relay — which is to say from anybody. A test that fed it two bytes found
    // this; without the check a stranger can stop the node by posting an event
    // with a short signature.
    if raw.len() != 64 {
        return Err(EventError::Malformed);
    }
    let signature = Signature::try_from(raw.as_slice()).map_err(|_| EventError::Malformed)?;
    // Prehash on this side too, for the same reason: the message BIP-340
    // signs here is the id itself.
    verifying
        .verify_prehash(&id, &signature)
        .map_err(|_| EventError::BadSignature)
}

/// The value of the first tag with this name, if any.
pub fn tag_value<'a>(event: &'a Event, name: &str) -> Option<&'a str> {
    event
        .tags
        .iter()
        .find(|t| t.first().is_some_and(|n| n == name))
        .and_then(|t| t.get(1))
        .map(String::as_str)
}

/// Lower-case hex, as every field Nostr carries in JSON is written.
pub fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32]).expect("a valid scalar")
    }

    #[test]
    fn the_bytes_hashed_for_the_id_are_the_ones_nip01_describes() {
        // Exact, because every relay recomputes this and drops anything whose
        // id does not match. No whitespace, the array in that order, and the
        // escaping NIP-01 asks for: the named escapes for the control
        // characters that have them, raw UTF-8 for everything else.
        let s = serialize_for_id(
            "aa".repeat(32).as_str(),
            1700000000,
            30078,
            &[vec!["d".to_owned(), "veil".to_owned()]],
            "a \"quote\", a \\ and a \n",
        );
        assert_eq!(
            s,
            format!(
                r#"[0,"{}",1700000000,30078,[["d","veil"]],"a \"quote\", a \\ and a \n"]"#,
                "aa".repeat(32)
            )
        );
        // No whitespace BETWEEN tokens — the spaces above are inside the
        // content, where they belong. A pretty-printer here would change
        // every id this node computes.
        let structural = serialize_for_id("cc", 1, 1, &[vec!["d".to_owned(), "x".to_owned()]], "y");
        assert_eq!(structural, r#"[0,"cc",1,1,[["d","x"]],"y"]"#);

        // Non-ASCII stays raw rather than becoming \u escapes.
        let cyrillic = serialize_for_id("bb", 1, 1, &[], "привет");
        assert!(
            cyrillic.contains("привет"),
            "content was \\u-escaped: {cyrillic}"
        );
    }

    #[test]
    fn an_event_this_signs_is_one_it_accepts() {
        let k = key(7);
        let event = sign(
            &k,
            1700000000,
            KIND_APP_DATA,
            vec![vec!["d".to_owned(), "veil-rendezvous".to_owned()]],
            "obfs4-tcp://198.51.100.4:5556",
        );
        assert_eq!(verify(&event), Ok(()));
        assert_eq!(event.pubkey.len(), 64, "a pubkey is 32 bytes of hex");
        assert_eq!(event.id.len(), 64);
        assert_eq!(event.sig.len(), 128, "a schnorr signature is 64 bytes");
        assert_eq!(tag_value(&event, "d"), Some("veil-rendezvous"));
        assert_eq!(tag_value(&event, "missing"), None);
    }

    #[test]
    fn the_id_is_signed_raw_and_not_hashed_again() {
        // The defect this pins cost a live run to find, and no unit test could
        // have: `k256`'s `Signer::sign` hashes the message with SHA-256 first,
        // Nostr signs the id RAW. Doing it the hashing way produces signatures
        // this crate verified happily and every relay rejected with
        // "invalid: bad signature" — our reader agreed with our writer and
        // both were wrong.
        //
        // So: a signature made the hashing way must NOT verify here.
        use k256::schnorr::signature::Signer as _;
        let k = key(21);
        let mut event = sign(&k, 1700000000, KIND_APP_DATA, vec![], "x");
        assert_eq!(verify(&event), Ok(()));

        let id = event_id(
            &event.pubkey,
            event.created_at,
            event.kind,
            &event.tags,
            &event.content,
        );
        let hashed: Signature = k.sign(&id);
        event.sig = hex_lower(&hashed.to_bytes());
        assert_eq!(
            verify(&event),
            Err(EventError::BadSignature),
            "a signature over sha256(id) was accepted; that is the one every \
             relay refuses"
        );
    }

    #[test]
    fn changing_anything_the_id_covers_is_caught() {
        // The id is the only thing binding the signature to the content, so
        // every field it covers has to be re-hashed on the way in.
        let k = key(9);
        let good = sign(&k, 1700000000, KIND_APP_DATA, vec![], "here");
        for tamper in [
            Event {
                content: "there".to_owned(),
                ..good.clone()
            },
            Event {
                created_at: good.created_at + 1,
                ..good.clone()
            },
            Event {
                kind: good.kind + 1,
                ..good.clone()
            },
            Event {
                tags: vec![vec!["d".to_owned(), "x".to_owned()]],
                ..good.clone()
            },
        ] {
            assert_eq!(
                verify(&tamper),
                Err(EventError::IdMismatch),
                "a changed field was not noticed"
            );
        }
    }

    #[test]
    fn a_signature_that_belongs_to_another_event_is_refused() {
        // The failure this closes: verifying the signature WITHOUT recomputing
        // the id accepts an event whose content was swapped for one signed
        // over a different id. Here the id and content agree with each other
        // and the signature belongs to neither.
        let k = key(3);
        let a = sign(&k, 1700000000, KIND_APP_DATA, vec![], "one");
        let b = sign(&k, 1700000000, KIND_APP_DATA, vec![], "two");
        let frankenstein = Event {
            sig: b.sig.clone(),
            ..a.clone()
        };
        assert_eq!(verify(&frankenstein), Err(EventError::BadSignature));
        // And one signed by somebody else entirely.
        let other = sign(&key(4), 1700000000, KIND_APP_DATA, vec![], "one");
        assert_eq!(
            verify(&Event {
                sig: other.sig,
                ..a.clone()
            }),
            Err(EventError::BadSignature)
        );
        // A pubkey swap changes the id, so that is caught earlier.
        assert_eq!(
            verify(&Event {
                pubkey: other.pubkey,
                ..a
            }),
            Err(EventError::IdMismatch)
        );
    }

    #[test]
    fn rubbish_in_the_hex_fields_is_refused_and_does_not_panic() {
        let k = key(11);
        let good = sign(&k, 1700000000, KIND_APP_DATA, vec![], "x");
        for bad in [
            Event {
                sig: "zz".repeat(64),
                ..good.clone()
            },
            Event {
                sig: "ab".to_owned(),
                ..good.clone()
            },
            Event {
                sig: String::new(),
                ..good.clone()
            },
            Event {
                sig: "abc".to_owned(),
                ..good.clone()
            },
        ] {
            assert!(verify(&bad).is_err(), "a malformed signature was accepted");
        }
        // A pubkey that is not a point at all: the id changes with it, so this
        // is refused before the curve is ever asked.
        assert!(
            verify(&Event {
                pubkey: "zz".repeat(32),
                ..good.clone()
            })
            .is_err()
        );
        assert!(
            verify(&Event {
                id: "00".repeat(32),
                ..good
            })
            .is_err()
        );
    }

    #[test]
    fn the_kind_is_the_addressable_one_a_relay_will_replace() {
        // 30000-39999 is the addressable range: a relay keeps only the latest
        // event per (pubkey, kind, d). An announcement that piled up instead
        // of replacing itself would leave a relay holding every address this
        // node ever had.
        assert!(
            (30000..40000).contains(&KIND_APP_DATA),
            "kind {KIND_APP_DATA} is not addressable, so announcements accumulate"
        );
    }
}
