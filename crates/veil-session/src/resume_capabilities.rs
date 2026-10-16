//! Current capabilities on the resume fast path, authenticated with its fresh
//! directional session keys. Legacy peers ignore the optional ATTACH trailer.
//! No transport role or scheduling priority is transmitted here.

use subtle::ConstantTimeEq;
use veil_proto::session::{AttachPayload, CapabilitiesPayload, RESUME_CAPABILITIES_TLV_TAG};

const MARKER: &[u8; 16] = b"VEIL-RES-CAPS-01";
const DOMAIN: &[u8] = b"veil/resume-capabilities/v1";
const MARKER2: &[u8; 16] = b"VEIL-RES-CAPS-02";
const DOMAIN2: &[u8] = b"veil/resume-capabilities/v2";
const CAPS_LEN: usize = 5; // version, roles, flags, discovery mode, extra flags
const VALUE_LEN: usize = MARKER.len() + CAPS_LEN + 32;
const VALUE_LEN2: usize = MARKER2.len() + 2 + 32;

fn mac(
    key: &[u8; 32],
    sender: &[u8; 32],
    receiver: &[u8; 32],
    attach_prefix: &[u8],
    caps: &[u8],
    version: u8,
) -> [u8; 32] {
    let mut hash = blake3::Hasher::new_keyed(key);
    hash.update(if version == 2 { DOMAIN2 } else { DOMAIN });
    hash.update(sender);
    hash.update(receiver);
    hash.update(attach_prefix);
    hash.update(if version == 2 { MARKER2 } else { MARKER });
    hash.update(caps);
    *hash.finalize().as_bytes()
}

pub(crate) fn append(
    attach: &mut Vec<u8>,
    caps: &CapabilitiesPayload,
    tx_key: &[u8; 32],
    sender: &[u8; 32],
    receiver: &[u8; 32],
) {
    let data = [
        1,
        caps.roles_supported,
        caps.flags,
        caps.discovery_mode,
        caps.extra_flags,
    ];
    let proof = mac(tx_key, sender, receiver, attach, &data, 1);
    attach.extend_from_slice(&RESUME_CAPABILITIES_TLV_TAG.to_be_bytes());
    attach.extend_from_slice(&(VALUE_LEN as u16).to_be_bytes());
    attach.extend_from_slice(MARKER);
    attach.extend_from_slice(&data);
    attach.extend_from_slice(&proof);
    if caps.extra_flags2 != 0 {
        // Keep the original recognized TLV byte-for-byte compatible. Old
        // verifiers skip this separately marked extension; new ones bind it
        // to the entire authenticated prefix, including the original proof.
        let data = [1, caps.extra_flags2];
        let proof = mac(tx_key, sender, receiver, attach, &data, 2);
        attach.extend_from_slice(&RESUME_CAPABILITIES_TLV_TAG.to_be_bytes());
        attach.extend_from_slice(&(VALUE_LEN2 as u16).to_be_bytes());
        attach.extend_from_slice(MARKER2);
        attach.extend_from_slice(&data);
        attach.extend_from_slice(&proof);
    }
}

/// Missing metadata keeps legacy fallback. A recognized malformed, duplicated
/// or unauthenticated extension fails the handshake rather than enabling bits.
/// The explicit marker distinguishes metadata from random handshake padding.
pub(crate) fn verify(
    attach: &[u8],
    rx_key: &[u8; 32],
    sender: &[u8; 32],
    receiver: &[u8; 32],
) -> Result<Option<CapabilitiesPayload>, &'static str> {
    let mut found = None;
    let mut extended = false;
    let mut pos = AttachPayload::WIRE_SIZE;
    while pos + 4 <= attach.len() {
        let tag = u16::from_be_bytes([attach[pos], attach[pos + 1]]);
        let len = u16::from_be_bytes([attach[pos + 2], attach[pos + 3]]) as usize;
        let start = pos + 4;
        let recognized = tag == RESUME_CAPABILITIES_TLV_TAG
            && attach.get(start..start + MARKER.len()) == Some(MARKER.as_slice());
        if recognized {
            if found.is_some() || len != VALUE_LEN || start + len > attach.len() {
                return Err("invalid resumed capability metadata");
            }
            let data = &attach[start + MARKER.len()..start + MARKER.len() + CAPS_LEN];
            if data[0] != 1 {
                return Err("unsupported resumed capability version");
            }
            let expected = mac(rx_key, sender, receiver, &attach[..pos], data, 1);
            if !bool::from(expected.ct_eq(&attach[start + len - 32..start + len])) {
                return Err("invalid resumed capability proof");
            }
            found = Some(CapabilitiesPayload {
                extra_flags2: 0,
                roles_supported: data[1],
                flags: data[2],
                discovery_mode: data[3],
                extra_flags: data[4],
            });
        } else if tag == RESUME_CAPABILITIES_TLV_TAG
            && attach.get(start..start + MARKER2.len()) == Some(MARKER2.as_slice())
        {
            if extended || found.is_none() || len != VALUE_LEN2 || start + len > attach.len() {
                return Err("invalid second resumed capability metadata");
            }
            let data = &attach[start + MARKER2.len()..start + MARKER2.len() + 2];
            if data[0] != 1 {
                return Err("unsupported second resumed capability version");
            }
            let expected = mac(rx_key, sender, receiver, &attach[..pos], data, 2);
            if !bool::from(expected.ct_eq(&attach[start + len - 32..start + len])) {
                return Err("invalid second resumed capability proof");
            }
            found.as_mut().expect("base verified above").extra_flags2 = data[1];
            extended = true;
        }
        if start + len > attach.len() {
            break; // Random padding or an unknown truncated optional trailer.
        }
        pos = start + len;
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_proto::session::{append_resume_nonce_to_attach, cap_flags};

    fn fixture() -> (Vec<u8>, CapabilitiesPayload) {
        let mut attach = vec![0; AttachPayload::WIRE_SIZE];
        append_resume_nonce_to_attach(&mut attach, &[8; 32]);
        let caps = CapabilitiesPayload {
            extra_flags2: 0,
            roles_supported: 1,
            flags: cap_flags::NO_DHT_SERVICE | cap_flags::SUPPORTS_REALTIME_DATAGRAMS,
            discovery_mode: 2,
            extra_flags: 15,
        };
        append(&mut attach, &caps, &[3; 32], &[1; 32], &[2; 32]);
        (attach, caps)
    }

    #[test]
    fn authentic_current_caps_survive_random_padding() {
        let (attach, caps) = fixture();
        for _ in 0..200 {
            let padded = crate::handshake::pad_handshake_body(&attach);
            assert_eq!(
                verify(&padded, &[3; 32], &[1; 32], &[2; 32]).unwrap(),
                Some(caps.clone())
            );
        }
    }

    #[test]
    fn reliable_child_permission_is_fresh_authenticated_resume_metadata() {
        use veil_proto::session::cap_extra_flags;
        let mut attach = vec![0; AttachPayload::WIRE_SIZE];
        let caps = CapabilitiesPayload {
            extra_flags2: 0,
            roles_supported: 1,
            flags: cap_flags::SUPPORTS_REALTIME_DATAGRAMS
                | cap_flags::SUPPORTS_DATAGRAM_FLOWS
                | cap_flags::SUPPORTS_REALTIME_REKEY,
            discovery_mode: 0,
            extra_flags: cap_extra_flags::SUPPORTS_PARALLEL_ORDERED
                | cap_extra_flags::SUPPORTS_RELIABLE_PARALLEL,
        };
        append(&mut attach, &caps, &[3; 32], &[1; 32], &[2; 32]);
        assert!(
            verify(&attach, &[3; 32], &[1; 32], &[2; 32])
                .unwrap()
                .unwrap()
                .supports_reliable_parallel()
        );
        let extra = AttachPayload::WIRE_SIZE + 4 + MARKER.len() + 4;
        attach[extra] ^= cap_extra_flags::SUPPORTS_RELIABLE_PARALLEL;
        assert!(
            verify(&attach, &[3; 32], &[1; 32], &[2; 32]).is_err(),
            "capability downgrade/upgrade must invalidate authentication"
        );
    }

    #[test]
    fn delivery_permission_is_bound_to_the_original_resume_proof_and_is_optional_for_legacy() {
        let mut caps = CapabilitiesPayload::from_node_role(veil_types::NodeRole::Core);
        caps.flags = u8::MAX;
        caps.extra_flags = u8::MAX;
        caps.extra_flags2 = veil_proto::session::cap_extra_flags2::SUPPORTS_RELIABLE_DELIVERY;
        let mut attach = vec![0; AttachPayload::WIRE_SIZE];
        append(&mut attach, &caps, &[3; 32], &[1; 32], &[2; 32]);
        assert!(
            verify(&attach, &[3; 32], &[1; 32], &[2; 32])
                .unwrap()
                .unwrap()
                .supports_reliable_delivery()
        );
        let second = AttachPayload::WIRE_SIZE + 4 + VALUE_LEN;
        let legacy = verify(&attach[..second], &[3; 32], &[1; 32], &[2; 32])
            .unwrap()
            .unwrap();
        assert!(legacy.supports_reliable_parallel());
        assert!(!legacy.supports_reliable_delivery());
        let mut forged = attach.clone();
        forged[second + 4 + MARKER2.len() + 1] ^= 1;
        assert!(verify(&forged, &[3; 32], &[1; 32], &[2; 32]).is_err());
        let mut duplicate = attach.clone();
        duplicate.extend_from_slice(&attach[second..]);
        assert!(verify(&duplicate, &[3; 32], &[1; 32], &[2; 32]).is_err());
        let mut orphan = vec![0; AttachPayload::WIRE_SIZE];
        orphan.extend_from_slice(&attach[second..]);
        assert!(verify(&orphan, &[3; 32], &[1; 32], &[2; 32]).is_err());
    }

    #[test]
    fn legacy_attach_and_unknown_trailers_do_not_enable_capabilities() {
        let mut attach = vec![0; AttachPayload::WIRE_SIZE];
        append_resume_nonce_to_attach(&mut attach, &[8; 32]);
        for _ in 0..200 {
            let padded = crate::handshake::pad_handshake_body(&attach);
            assert_eq!(verify(&padded, &[3; 32], &[1; 32], &[2; 32]).unwrap(), None);
        }
        attach.extend_from_slice(&RESUME_CAPABILITIES_TLV_TAG.to_be_bytes());
        attach.extend_from_slice(&4u16.to_be_bytes());
        attach.extend_from_slice(&[1, 2, 3, 4]);
        assert_eq!(verify(&attach, &[3; 32], &[1; 32], &[2; 32]).unwrap(), None);
    }

    #[test]
    fn tampering_fields_nonce_prefix_or_proof_fails() {
        let (attach, _) = fixture();
        let offset = AttachPayload::WIRE_SIZE + 4 + 32 + 4 + MARKER.len();
        for index in [
            0,
            AttachPayload::WIRE_SIZE + 4,
            offset + 1,
            offset + 2,
            offset + 3,
            offset + 4,
            attach.len() - 1,
        ] {
            let mut bad = attach.clone();
            bad[index] ^= 1;
            assert!(
                verify(&bad, &[3; 32], &[1; 32], &[2; 32]).is_err(),
                "tamper at {index}"
            );
        }
    }

    #[test]
    fn old_key_other_peer_and_reflection_cannot_authenticate() {
        let (attach, _) = fixture();
        assert!(verify(&attach, &[4; 32], &[1; 32], &[2; 32]).is_err());
        assert!(verify(&attach, &[3; 32], &[9; 32], &[2; 32]).is_err());
        assert!(verify(&attach, &[3; 32], &[1; 32], &[9; 32]).is_err());
        assert!(verify(&attach, &[3; 32], &[2; 32], &[1; 32]).is_err());
    }

    #[test]
    fn duplicate_truncated_and_wrong_length_metadata_fails() {
        let (attach, caps) = fixture();
        let mut duplicate = attach.clone();
        append(&mut duplicate, &caps, &[3; 32], &[1; 32], &[2; 32]);
        assert!(verify(&duplicate, &[3; 32], &[1; 32], &[2; 32]).is_err());
        let mut truncated = attach.clone();
        truncated.pop();
        assert!(verify(&truncated, &[3; 32], &[1; 32], &[2; 32]).is_err());
        let mut wrong_length = attach;
        wrong_length[AttachPayload::WIRE_SIZE + 4 + 32 + 3] -= 1;
        assert!(verify(&wrong_length, &[3; 32], &[1; 32], &[2; 32]).is_err());
    }
}
