use super::*;

fn modern() -> CapabilitiesPayload {
    let mut caps = CapabilitiesPayload::from_node_role(veil_types::NodeRole::Core);
    caps.flags = u8::MAX;
    caps.extra_flags = u8::MAX;
    caps.extra_flags2 = cap_extra_flags2::SUPPORTS_RELIABLE_DELIVERY;
    caps
}

#[test]
fn second_extension_preserves_the_complete_legacy_capability_prefix() {
    let caps = modern();
    let wire = caps.encode();
    assert_eq!(wire.len(), 37);
    assert!(
        CapabilitiesPayload::decode(&wire)
            .unwrap()
            .supports_reliable_delivery()
    );
    let mut old = caps.clone();
    old.extra_flags2 = 0;
    assert_eq!(&wire[..20], old.encode());
    let legacy_view = CapabilitiesPayload::decode(&wire[..20]).unwrap();
    assert!(legacy_view.supports_reliable_parallel());
    assert!(legacy_view.supports_parallel_ordered());
    assert!(!legacy_view.supports_reliable_delivery());
}

#[test]
fn random_padding_partial_markers_and_missing_parent_permissions_never_enable_delivery() {
    let wire = modern().encode();
    for len in 20..wire.len() {
        assert!(
            !CapabilitiesPayload::decode(&wire[..len])
                .unwrap()
                .supports_reliable_delivery()
        );
    }
    for index in 20..36 {
        let mut corrupt = wire.clone();
        corrupt[index] ^= 1;
        let decoded = CapabilitiesPayload::decode(&corrupt).unwrap();
        assert!(decoded.supports_reliable_parallel());
        assert!(!decoded.supports_reliable_delivery());
    }
    let mut padding = wire[..20].to_vec();
    padding.extend_from_slice(&[0xa5; 64]);
    assert!(
        !CapabilitiesPayload::decode(&padding)
            .unwrap()
            .supports_reliable_delivery()
    );
    let mut no_parent = modern();
    no_parent.extra_flags &= !cap_extra_flags::SUPPORTS_RELIABLE_PARALLEL;
    assert!(
        !CapabilitiesPayload::decode(&no_parent.encode())
            .unwrap()
            .supports_reliable_delivery()
    );
    let mut no_marker = wire;
    no_marker[3] ^= 1;
    assert_eq!(
        CapabilitiesPayload::decode(&no_marker)
            .unwrap()
            .extra_flags2,
        0
    );
}

#[test]
fn zero_extensions_retain_the_original_three_byte_encoding() {
    let caps = CapabilitiesPayload::from_node_role(veil_types::NodeRole::Core);
    assert_eq!(
        caps.encode(),
        vec![caps.roles_supported, caps.flags, caps.discovery_mode]
    );
}
