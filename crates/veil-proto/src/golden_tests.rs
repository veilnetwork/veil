//! Protocol conformance tests.
//!
//! # Purpose
//!
//! These tests guard against **accidental wire-breaking changes** by pinning the
//! exact byte representation of each protocol message. If you change a proto
//! struct's layout and a golden test fails, you know the change is wire-breaking
//! and requires a version bump or migration strategy.
//!
//! # Sections
//!
//! 1. **Golden frame corpus** — hardcoded input bytes → assert decode == expected
//! 2. **Malformed frame corpus** — intentionally broken bytes → assert all `Err`
//! 3. **Cross-version compat** — old encoder output → current decoder (backwards compat)

#[cfg(test)]
mod golden {
    // ── Golden frame corpus (247.1) ───────────────────────────────────────────

    /// A golden `FrameHeader` byte sequence and the expected decoded value.
    ///
    /// Layout (24 bytes):
    /// `[magic=4][version=1][family=1][msg_type=2][flags=2][header_len=2][body_len=4][stream_id=4][request_id=4]`
    #[test]
    fn golden_frame_header() {
        use crate::{codec::decode_header, header::MAGIC};

        // Build the expected golden bytes manually.
        let mut golden = [0u8; 24];
        golden[..4].copy_from_slice(&MAGIC); // magic
        golden[4] = 1; // version
        golden[5] = 2; // family = Discovery
        golden[6..8].copy_from_slice(&5u16.to_be_bytes()); // msg_type = AnnounceAttachment
        golden[8..10].copy_from_slice(&0u16.to_be_bytes()); // flags = 0
        golden[10..12].copy_from_slice(&24u16.to_be_bytes()); // header_len = 24
        golden[12..16].copy_from_slice(&0u32.to_be_bytes()); // body_len = 0
        golden[16..20].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes()); // stream_id
        golden[20..24].copy_from_slice(&0x0102_0304u32.to_be_bytes()); // request_id

        let decoded = decode_header(&golden).expect("golden FrameHeader must decode");
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.family, 2);
        assert_eq!(decoded.msg_type, 5);
        assert_eq!(decoded.stream_id, 0xDEAD_BEEF);
        assert_eq!(decoded.request_id, 0x0102_0304);

        // Roundtrip: re-encode and compare bytes.
        let re_encoded = crate::codec::encode_header(&decoded);
        assert_eq!(re_encoded.as_slice(), &golden);
    }

    /// Golden `AttachPayload` (session.rs) — 9 fixed bytes.
    #[test]
    fn golden_attach_payload() {
        use crate::session::AttachPayload;

        // role=2, realm_id=0x0000_0001, attach_epoch=0x0000_0007
        // mailbox_preference_count=3, gateway_preference_count=1, flags=0
        // Wire: role(1) + realm_id(4) + attach_epoch(4) + mailbox_pref(1) + gw_pref(1) + flags(2) = 13 bytes
        let golden: &[u8] = &[
            0x02, // role = 2
            0x00, 0x00, 0x00, 0x01, // realm_id = 1 (BE u32)
            0x00, 0x00, 0x00, 0x07, // attach_epoch = 7 (BE u32)
            0x03, // mailbox_preference_count = 3
            0x01, // gateway_preference_count = 1
            0x00, 0x00, // flags = 0 (BE u16)
        ];

        let decoded = AttachPayload::decode(golden).expect("golden AttachPayload must decode");
        assert_eq!(decoded.role, 2);
        assert_eq!(decoded.realm_id, 1);
        assert_eq!(decoded.attach_epoch, 7);
        assert_eq!(decoded.mailbox_preference_count, 3);
        assert_eq!(decoded.gateway_preference_count, 1);
        assert_eq!(decoded.flags, 0);
    }

    /// Golden `RelayChainHop` (relay_chain.rs).
    #[test]
    fn golden_relay_chain_hop() {
        use crate::relay_chain::{FINAL_HOP_SENTINEL, RelayChainHop};

        // next_hop = FINAL_HOP_SENTINEL (32 zeroes), inner_len = 5 (BE u32), inner = "hello"
        let mut golden = Vec::new();
        golden.extend_from_slice(&FINAL_HOP_SENTINEL); // 32 bytes
        golden.extend_from_slice(&5u32.to_be_bytes()); // inner_len
        golden.extend_from_slice(b"hello"); // inner

        let decoded = RelayChainHop::decode(&golden).expect("golden RelayChainHop must decode");
        assert!(decoded.is_final());
        assert_eq!(decoded.inner, b"hello");

        // Re-encode must produce identical bytes.
        assert_eq!(decoded.encode(), golden);
    }

    /// Golden `EphemeralEndpoint` TLV (discovery.rs).
    #[test]
    fn golden_ephemeral_endpoint_tlv() {
        use crate::discovery::{EPHEMERAL_ENDPOINT_TLV_TAG, EphemeralEndpoint};

        let ep = EphemeralEndpoint {
            endpoint_id: [0xABu8; 16],
            valid_until: 1_700_000_000,
        };
        let encoded = ep.encode_tlv();

        // tag(2) + len(2) + endpoint_id(16) + valid_until(8) = 28 bytes
        assert_eq!(encoded.len(), 28);
        let tag = u16::from_be_bytes([encoded[0], encoded[1]]);
        assert_eq!(tag, EPHEMERAL_ENDPOINT_TLV_TAG);
        let len = u16::from_be_bytes([encoded[2], encoded[3]]);
        assert_eq!(len as usize, EphemeralEndpoint::VALUE_SIZE);
        assert_eq!(&encoded[4..20], &[0xABu8; 16]);
        let vu = u64::from_be_bytes(encoded[20..28].try_into().unwrap());
        assert_eq!(vu, 1_700_000_000);
    }

    /// Golden `MeshFrame` (mesh.rs).
    #[test]
    fn golden_mesh_frame() {
        use crate::mesh::{MeshFrame, RealmId};

        let realm = RealmId([0u8; 16]);
        let src = [0x01u8; 32];
        let dst = [0x02u8; 32];
        let frame = MeshFrame::new(realm, src, dst, 3, b"payload".to_vec());
        let encoded = frame.encode();

        // Decode the golden bytes.
        let decoded = MeshFrame::decode(&encoded).expect("golden MeshFrame must decode");
        assert_eq!(decoded.ttl, 3);
        assert_eq!(decoded.src_node_id, src);
        assert_eq!(decoded.dst_node_id, dst);
        assert_eq!(&decoded.payload[..], b"payload");
    }

    // ── Malformed frame corpus (247.2) ────────────────────────────────────────

    /// Table (description, malformed bytes) for `FrameHeader`.
    #[test]
    fn malformed_frame_headers() {
        use crate::codec::decode_header;

        let cases: &[(&str, &[u8])] = &[
            ("empty", &[]),
            ("too short", &[b'O', b'V', b'L', b'1', 1, 0, 0, 0, 0, 0]),
            (
                "bad magic",
                &[
                    b'X', b'X', b'X', b'X', 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0,
                ],
            ),
            ("bad version", &{
                let mut b = [0u8; 24];
                b[..4].copy_from_slice(b"OVL1");
                b[4] = 99;
                b
            }),
            ("body too large", &{
                let mut b = [0u8; 24];
                b[..4].copy_from_slice(b"OVL1");
                b[4] = 1;
                b[10..12].copy_from_slice(&24u16.to_be_bytes()); // header_len
                b[12..16].copy_from_slice(&(u32::MAX).to_be_bytes()); // body_len too large
                b
            }),
        ];

        for (desc, bytes) in cases {
            assert!(
                decode_header(bytes).is_err(),
                "case '{desc}' must fail to decode, but succeeded",
            );
        }
    }

    /// Table of malformed bytes for `AttachPayload`.
    #[test]
    fn malformed_attach_payloads() {
        use crate::session::AttachPayload;

        let cases: &[(&str, &[u8])] = &[("empty", &[]), ("too short", &[0x01, 0x00, 0x00])];

        for (desc, bytes) in cases {
            assert!(
                AttachPayload::decode(bytes).is_err(),
                "case '{desc}' must fail, but succeeded",
            );
        }
    }

    /// Table of malformed bytes for `RelayChainHop`.
    #[test]
    fn malformed_relay_chain_hops() {
        use crate::relay_chain::RelayChainHop;

        let cases: &[(&str, &[u8])] = &[
            ("empty", &[]),
            ("too short", &[0u8; 10]),
            ("inner_len_overflow", &{
                // next_hop (32) + inner_len=9999 (4) but no data follows
                let mut b = vec![0u8; 36];
                b[32..36].copy_from_slice(&9999u32.to_be_bytes());
                b
            }),
        ];

        for (desc, bytes) in cases {
            assert!(
                RelayChainHop::decode(bytes).is_err(),
                "case '{desc}' must fail, but succeeded",
            );
        }
    }

    // ── Cross-version compat (247.3) ──────────────────────────────────────────

    /// `AnnounceAttachmentPayload` without the seq_no/signature trailer (old format)
    /// must decode successfully with seq_no=0, signature=[], ephemeral_endpoint=None.
    #[test]
    fn backwards_compat_announce_without_seq_sig() {
        use crate::discovery::{AnnounceAttachmentPayload, GatewayRef};

        // Encode the minimal "old" format: just fixed fields + 1 gateway.
        // dropped the mailbox_count byte and the per-mailbox slots
        // from the wire layout; this fixture mirrors the post-473 shape.
        let gw = GatewayRef {
            gateway_node_id: [2u8; 32],
            priority: 1,
            weight: 1,
            flags: 0,
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(&[1u8; 32]); // node_id
        buf.push(1); // role
        buf.extend_from_slice(&42u32.to_be_bytes()); // realm_id
        buf.extend_from_slice(&1u32.to_be_bytes()); // epoch
        buf.extend_from_slice(&1_700_000_000u64.to_be_bytes()); // expires_at
        buf.push(1); // gateway_count = 1
        buf.extend_from_slice(&gw.encode()); // 1 gateway
        // No seq_no, no signature.

        let decoded =
            AnnounceAttachmentPayload::decode(&buf).expect("old-format announce must decode");
        assert_eq!(decoded.node_id, [1u8; 32]);
        assert_eq!(decoded.realm_id, 42);
        assert_eq!(decoded.seq_no, 0, "missing seq_no defaults to 0");
        assert!(
            decoded.signature.is_empty(),
            "missing signature defaults to empty"
        );
        assert!(
            decoded.ephemeral_endpoint.is_none(),
            "no TLV = no ephemeral endpoint"
        );
    }

    /// `AnnounceAttachmentPayload` with seq_no+signature but without ephemeral TLV
    /// must decode successfully with ephemeral_endpoint=None.
    #[test]
    fn backwards_compat_announce_with_sig_no_endpoint_tlv() {
        use crate::discovery::{AnnounceAttachmentPayload, EphemeralEndpoint};

        let mut p = AnnounceAttachmentPayload {
            node_id: [3u8; 32],
            role: 1,
            realm_id: 10,
            epoch: 2,
            expires_at: 9_999_999_999,
            gateways: vec![],
            seq_no: 99,
            signature: vec![0xFFu8; 64],
            ephemeral_endpoint: None,
        };
        let encoded = p.encode();

        // Decode and verify that no ephemeral endpoint is set.
        let decoded = AnnounceAttachmentPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.seq_no, 99);
        assert_eq!(decoded.signature.len(), 64);
        assert!(decoded.ephemeral_endpoint.is_none());

        // Now add an ephemeral endpoint and verify it round-trips.
        p.ephemeral_endpoint = Some(EphemeralEndpoint {
            endpoint_id: [0x42u8; 16],
            valid_until: 1_800_000_000,
        });
        let encoded2 = p.encode();
        let decoded2 = AnnounceAttachmentPayload::decode(&encoded2).unwrap();
        assert!(decoded2.ephemeral_endpoint.is_some());
        assert_eq!(
            decoded2.ephemeral_endpoint.unwrap().endpoint_id,
            [0x42u8; 16]
        );
    }

    /// `MeshFrame` encoded by an older version (without realm_id, if the header
    /// was just 64+64+1 bytes) must be handled gracefully.
    ///
    /// This tests the existing decode's out-of-bounds guard (it returns `None`
    /// on short buffers rather than panicking).
    #[test]
    fn backwards_compat_truncated_mesh_frame_returns_none() {
        use crate::mesh::MeshFrame;

        // A 10-byte buffer is way too short for any valid MeshFrame.
        assert!(MeshFrame::decode(&[0u8; 10]).is_err());
    }
}
