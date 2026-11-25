//! Owner-signed virtual address snapshots. This format only assigns
//! addresses; a current daemon membership is still required to forward traffic.

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};
use serde::Deserialize;
use veil_types::SignatureAlgorithm;

// The version and domain are part of the signature input. The body is
// fixed-width and big-endian, with members ordered by node ID.
const DOMAIN: &[u8] = b"veil/p-net/route-policy/v1\0";
const HEADER_SIZE: usize = DOMAIN.len() + 32 + 1 + 8 * 3 + 5 + 17 + 2;
const MEMBER_SIZE: usize = 32 + 1 + 4 + 16;
const ABSENT_PREFIX: u8 = 255;
const MAX_SIGNATURE_BYTES: usize = 2048;
pub const MAX_ROUTE_POLICY_MEMBERS: usize = 4096;
pub const MAX_SIGNED_ROUTE_POLICY_BYTES: usize =
    HEADER_SIZE + MAX_ROUTE_POLICY_MEMBERS * MEMBER_SIZE + MAX_SIGNATURE_BYTES;

/// The trust anchor is pinned by the operator independently of the snapshot.
pub struct RoutePolicyAuthority<'a> {
    pub network_id: [u8; 32],
    pub algorithm: SignatureAlgorithm,
    pub public_key: &'a str,
}

/// Address assignments comprising one complete snapshot. An empty member list
/// is valid and withdraws all addresses at a higher revision.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoutePolicy {
    #[serde(deserialize_with = "deserialize_id")]
    pub network_id: [u8; 32],
    pub revision: u64,
    pub valid_from_unix: u64,
    pub valid_until_unix: u64,
    pub ipv4_range: Option<Ipv4Net>,
    pub ipv6_range: Option<Ipv6Net>,
    #[serde(default)]
    pub members: Vec<RoutePolicyMember>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoutePolicyMember {
    #[serde(deserialize_with = "deserialize_id")]
    pub node_id: [u8; 32],
    pub addr_v4: Option<Ipv4Addr>,
    pub addr_v6: Option<Ipv6Addr>,
}

/// A snapshot verified against the operator's pinned owner and network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRoutePolicy(RoutePolicy);

/// A verified offer bound to its original signed bytes and owner pin.
#[cfg(unix)]
pub struct VerifiedRoutePolicyOffer {
    policy: VerifiedRoutePolicy,
    signed: Vec<u8>,
    owner_algorithm: SignatureAlgorithm,
    owner_key: String,
}

#[cfg(unix)]
impl VerifiedRoutePolicyOffer {
    /// Authenticate the offered bytes. The store checks validity again at acceptance.
    pub fn verify(
        signed: Vec<u8>,
        authority: &RoutePolicyAuthority<'_>,
    ) -> Result<Self, RoutePolicyError> {
        let policy = verify_route_policy(&signed, authority)?;
        Ok(Self {
            policy,
            signed,
            owner_algorithm: authority.algorithm,
            owner_key: authority.public_key.to_owned(),
        })
    }

    /// The authenticated policy used to compare mirror offers.
    pub fn policy(&self) -> &VerifiedRoutePolicy {
        &self.policy
    }

    pub(crate) fn matches_authority(&self, authority: &RoutePolicyAuthority<'_>) -> bool {
        self.policy.network_id == authority.network_id
            && self.owner_algorithm == authority.algorithm
            && self.owner_key == authority.public_key
    }

    pub(crate) fn into_parts(self) -> (VerifiedRoutePolicy, Vec<u8>) {
        (self.policy, self.signed)
    }
}

impl std::ops::Deref for VerifiedRoutePolicy {
    type Target = RoutePolicy;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RoutePolicyError {
    #[error("signed route policy has an invalid format or version")]
    Format,
    #[error("route policy belongs to a different P-Net")]
    WrongNetwork,
    #[error("route policy uses a different owner algorithm")]
    WrongAlgorithm,
    #[error("route policy signature: {0}")]
    Signature(#[source] veil_error::ConfigError),
    #[error("route policy revision must be positive")]
    InvalidRevision,
    #[error("route policy must have a finite validity window with start before expiry")]
    InvalidWindow,
    #[error("route policy clock is unavailable")]
    ClockUnavailable,
    #[error("route policy is valid from {0} (Unix seconds)")]
    NotYetValid(u64),
    #[error("route policy expired at {0} (Unix seconds)")]
    Expired(u64),
    #[error("route policy has more than {MAX_ROUTE_POLICY_MEMBERS} members")]
    TooManyMembers,
    #[error("route policy must specify at least one canonical address range")]
    InvalidRange,
    #[error("route policy repeats a member node ID")]
    DuplicateMember,
    #[error("route policy member has a zero node ID or no virtual address")]
    InvalidMember,
    #[error("route policy repeats virtual address {0}")]
    DuplicateAddress(std::net::IpAddr),
    #[error("virtual address {0} is unusable or outside the signed address range")]
    InvalidAddress(std::net::IpAddr),
}

fn deserialize_id<'de, D: serde::Deserializer<'de>>(de: D) -> Result<[u8; 32], D::Error> {
    let text = String::deserialize(de)?;
    veil_util::hex_to_array(&text)
        .map_err(|_| serde::de::Error::custom("expected a 64-digit hexadecimal ID"))
}

impl RoutePolicy {
    pub fn check_current(&self, now: u64) -> Result<(), RoutePolicyError> {
        if now == 0 {
            return Err(RoutePolicyError::ClockUnavailable);
        }
        if now < self.valid_from_unix {
            return Err(RoutePolicyError::NotYetValid(self.valid_from_unix));
        }
        if now >= self.valid_until_unix {
            return Err(RoutePolicyError::Expired(self.valid_until_unix));
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), RoutePolicyError> {
        if self.network_id == [0; 32] {
            return Err(RoutePolicyError::WrongNetwork);
        }
        if self.revision == 0 {
            return Err(RoutePolicyError::InvalidRevision);
        }
        if self.valid_from_unix == 0 || self.valid_until_unix <= self.valid_from_unix {
            return Err(RoutePolicyError::InvalidWindow);
        }
        if self.members.len() > MAX_ROUTE_POLICY_MEMBERS {
            return Err(RoutePolicyError::TooManyMembers);
        }
        if (self.ipv4_range.is_none() && self.ipv6_range.is_none())
            || self
                .ipv4_range
                .is_some_and(|range| range.addr() != range.network())
            || self
                .ipv6_range
                .is_some_and(|range| range.addr() != range.network())
        {
            return Err(RoutePolicyError::InvalidRange);
        }
        let mut node_ids = HashSet::with_capacity(self.members.len());
        let mut addresses = HashSet::<std::net::IpAddr>::with_capacity(self.members.len());
        for entry in &self.members {
            if entry.node_id == [0; 32] || (entry.addr_v4.is_none() && entry.addr_v6.is_none()) {
                return Err(RoutePolicyError::InvalidMember);
            }
            if !node_ids.insert(entry.node_id) {
                return Err(RoutePolicyError::DuplicateMember);
            }
            if let Some(addr) = entry.addr_v4 {
                let usable = self.ipv4_range.is_some_and(|range| {
                    range.contains(&addr)
                        && (range.prefix_len() >= 31
                            || (addr != range.network() && addr != range.broadcast()))
                });
                if !usable
                    || addr.is_unspecified()
                    || addr.is_loopback()
                    || addr.is_multicast()
                    || addr.is_broadcast()
                    || addr.is_link_local()
                {
                    return Err(RoutePolicyError::InvalidAddress(addr.into()));
                }
                if !addresses.insert(addr.into()) {
                    return Err(RoutePolicyError::DuplicateAddress(addr.into()));
                }
            }
            if let Some(addr) = entry.addr_v6 {
                if !self.ipv6_range.is_some_and(|range| range.contains(&addr))
                    || addr.is_unspecified()
                    || addr.is_loopback()
                    || addr.is_multicast()
                    || addr.is_unicast_link_local()
                    || addr.to_ipv4_mapped().is_some()
                {
                    return Err(RoutePolicyError::InvalidAddress(addr.into()));
                }
                if !addresses.insert(addr.into()) {
                    return Err(RoutePolicyError::DuplicateAddress(addr.into()));
                }
            }
        }
        Ok(())
    }

    fn encode_body(&self, algorithm: SignatureAlgorithm) -> Vec<u8> {
        let mut body = Vec::with_capacity(HEADER_SIZE + self.members.len() * MEMBER_SIZE);
        body.extend_from_slice(DOMAIN);
        body.extend_from_slice(&self.network_id);
        body.push(algorithm.wire_byte());
        body.extend_from_slice(&self.revision.to_be_bytes());
        body.extend_from_slice(&self.valid_from_unix.to_be_bytes());
        body.extend_from_slice(&self.valid_until_unix.to_be_bytes());
        body.push(
            self.ipv4_range
                .map_or(ABSENT_PREFIX, |net| net.prefix_len()),
        );
        body.extend_from_slice(&self.ipv4_range.map_or([0; 4], |net| net.addr().octets()));
        body.push(
            self.ipv6_range
                .map_or(ABSENT_PREFIX, |net| net.prefix_len()),
        );
        body.extend_from_slice(&self.ipv6_range.map_or([0; 16], |net| net.addr().octets()));
        body.extend_from_slice(&(self.members.len() as u16).to_be_bytes());
        for entry in &self.members {
            body.extend_from_slice(&entry.node_id);
            body.push(u8::from(entry.addr_v4.is_some()) | (u8::from(entry.addr_v6.is_some()) << 1));
            body.extend_from_slice(&entry.addr_v4.map_or([0; 4], |addr| addr.octets()));
            body.extend_from_slice(&entry.addr_v6.map_or([0; 16], |addr| addr.octets()));
        }
        body
    }
}

pub fn sign_route_policy(
    mut policy: RoutePolicy,
    algorithm: SignatureAlgorithm,
    public_key: &str,
    private_key: &str,
) -> Result<Vec<u8>, RoutePolicyError> {
    policy.validate()?;
    policy.members.sort_unstable_by_key(|entry| entry.node_id);
    let mut body = policy.encode_body(algorithm);
    let signature = veil_crypto::sign_message(algorithm, public_key, private_key, &body)
        .map_err(RoutePolicyError::Signature)?;
    // Catch configuration mistakes such as a public key paired with a
    // different private key before distributing the resulting snapshot.
    veil_crypto::verify_message(algorithm, public_key, &body, &signature)
        .map_err(RoutePolicyError::Signature)?;
    if signature.is_empty() || signature.len() > MAX_SIGNATURE_BYTES {
        return Err(RoutePolicyError::Format);
    }
    body.extend_from_slice(&signature);
    Ok(body)
}

/// Verify structure, trust anchor and signature. Validity is checked
/// separately so an expired accepted policy still establishes its revision.
pub fn verify_route_policy(
    blob: &[u8],
    authority: &RoutePolicyAuthority<'_>,
) -> Result<VerifiedRoutePolicy, RoutePolicyError> {
    use RoutePolicyError::Format;
    if blob.len() > MAX_SIGNED_ROUTE_POLICY_BYTES {
        return Err(Format);
    }
    let mut remaining = blob.strip_prefix(DOMAIN).ok_or(Format)?;
    let network_id = take(&mut remaining)?;
    if network_id != authority.network_id {
        return Err(RoutePolicyError::WrongNetwork);
    }
    if take::<1>(&mut remaining)?[0] != authority.algorithm.wire_byte() {
        return Err(RoutePolicyError::WrongAlgorithm);
    }
    let revision = u64::from_be_bytes(take(&mut remaining)?);
    let valid_from_unix = u64::from_be_bytes(take(&mut remaining)?);
    let valid_until_unix = u64::from_be_bytes(take(&mut remaining)?);
    let prefix_v4 = take::<1>(&mut remaining)?[0];
    let range_v4 = take::<4>(&mut remaining)?;
    let prefix_v6 = take::<1>(&mut remaining)?[0];
    let range_v6 = take::<16>(&mut remaining)?;
    let count = usize::from(u16::from_be_bytes(take(&mut remaining)?));
    if count > MAX_ROUTE_POLICY_MEMBERS {
        return Err(RoutePolicyError::TooManyMembers);
    }
    let body_len = HEADER_SIZE + count * MEMBER_SIZE;
    let (body, signature) = blob.split_at_checked(body_len).ok_or(Format)?;
    if signature.is_empty() || signature.len() > MAX_SIGNATURE_BYTES {
        return Err(Format);
    }
    veil_crypto::verify_message(authority.algorithm, authority.public_key, body, signature)
        .map_err(RoutePolicyError::Signature)?;

    let ipv4_range = match prefix_v4 {
        ABSENT_PREFIX if range_v4 == [0; 4] => None,
        prefix => Some(Ipv4Net::new(range_v4.into(), prefix).map_err(|_| Format)?),
    };
    let ipv6_range = match prefix_v6 {
        ABSENT_PREFIX if range_v6 == [0; 16] => None,
        prefix => Some(Ipv6Net::new(range_v6.into(), prefix).map_err(|_| Format)?),
    };
    let mut entries = &body[HEADER_SIZE..];
    let mut members = Vec::with_capacity(count);
    for _ in 0..count {
        let node_id = take(&mut entries)?;
        let mask = take::<1>(&mut entries)?[0];
        let addr_v4 = take::<4>(&mut entries)?;
        let addr_v6 = take::<16>(&mut entries)?;
        if !(1..=3).contains(&mask)
            || (mask & 1 == 0 && addr_v4 != [0; 4])
            || (mask & 2 == 0 && addr_v6 != [0; 16])
        {
            return Err(Format);
        }
        members.push(RoutePolicyMember {
            node_id,
            addr_v4: (mask & 1 != 0).then(|| addr_v4.into()),
            addr_v6: (mask & 2 != 0).then(|| addr_v6.into()),
        });
    }
    let policy = RoutePolicy {
        network_id,
        revision,
        valid_from_unix,
        valid_until_unix,
        ipv4_range,
        ipv6_range,
        members,
    };
    policy.validate()?;
    if !policy.members.is_sorted_by_key(|entry| entry.node_id) {
        return Err(Format);
    }
    Ok(VerifiedRoutePolicy(policy))
}

fn take<const N: usize>(remaining: &mut &[u8]) -> Result<[u8; N], RoutePolicyError> {
    let (head, tail) = remaining
        .split_first_chunk::<N>()
        .ok_or(RoutePolicyError::Format)?;
    *remaining = tail;
    Ok(*head)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RoutePolicy {
        RoutePolicy {
            network_id: [42; 32],
            revision: 7,
            valid_from_unix: 1_000,
            valid_until_unix: 2_000,
            ipv4_range: Some("198.18.0.0/24".parse().unwrap()),
            ipv6_range: Some("fd84:7::/64".parse().unwrap()),
            members: vec![
                RoutePolicyMember {
                    node_id: [3; 32],
                    addr_v4: Some("198.18.0.3".parse().unwrap()),
                    addr_v6: None,
                },
                RoutePolicyMember {
                    node_id: [2; 32],
                    addr_v4: Some("198.18.0.2".parse().unwrap()),
                    addr_v6: Some("fd84:7::2".parse().unwrap()),
                },
            ],
        }
    }

    #[test]
    fn canonical_bytes_are_independent_of_input_order() {
        let algorithm = SignatureAlgorithm::Ed25519;
        let key = veil_crypto::generate_keypair(algorithm);
        let policy = sample();
        let authority = RoutePolicyAuthority {
            network_id: policy.network_id,
            algorithm,
            public_key: &key.public_key,
        };
        let signed =
            sign_route_policy(policy.clone(), algorithm, &key.public_key, &key.private_key)
                .unwrap();
        let mut ordered = policy;
        ordered.members.reverse();
        let sorted = sign_route_policy(
            ordered.clone(),
            algorithm,
            &key.public_key,
            &key.private_key,
        )
        .unwrap();
        assert_eq!(signed, sorted);
        let decoded = verify_route_policy(&signed, &authority).unwrap();
        assert_eq!(*decoded, ordered);
        assert!(matches!(
            decoded.check_current(999),
            Err(RoutePolicyError::NotYetValid(1000))
        ));
        assert!(decoded.check_current(1000).is_ok());
        assert!(decoded.check_current(1999).is_ok());
        assert!(matches!(
            decoded.check_current(2000),
            Err(RoutePolicyError::Expired(2000))
        ));
    }

    #[test]
    fn owner_signature_and_network_are_required_for_every_supported_algorithm() {
        for &algorithm in SignatureAlgorithm::supported() {
            let key = veil_crypto::generate_keypair(algorithm);
            let other = veil_crypto::generate_keypair(algorithm);
            let policy = sample();
            let mut authority = RoutePolicyAuthority {
                network_id: policy.network_id,
                algorithm,
                public_key: &key.public_key,
            };
            let signed =
                sign_route_policy(policy.clone(), algorithm, &key.public_key, &key.private_key)
                    .unwrap();
            assert!(verify_route_policy(&signed, &authority).is_ok());
            authority.network_id = [77; 32];
            assert!(matches!(
                verify_route_policy(&signed, &authority),
                Err(RoutePolicyError::WrongNetwork)
            ));
            authority.network_id = policy.network_id;
            authority.public_key = &other.public_key;
            assert!(matches!(
                verify_route_policy(&signed, &authority),
                Err(RoutePolicyError::Signature(_))
            ));
            authority.public_key = &key.public_key;
            let mut tampered = signed;
            tampered[HEADER_SIZE + 36] ^= 1;
            assert!(matches!(
                verify_route_policy(&tampered, &authority),
                Err(RoutePolicyError::Signature(_))
            ));
            assert!(matches!(
                sign_route_policy(policy, algorithm, &key.public_key, &other.private_key),
                Err(RoutePolicyError::Signature(_))
            ));
        }
    }

    #[test]
    fn ambiguous_and_out_of_range_assignments_are_rejected() {
        let mut policy = sample();
        policy.members[0].addr_v4 = policy.members[1].addr_v4;
        assert!(matches!(
            policy.validate(),
            Err(RoutePolicyError::DuplicateAddress(_))
        ));
        policy.members[0].addr_v4 = Some("198.18.1.44".parse().unwrap());
        assert!(matches!(
            policy.validate(),
            Err(RoutePolicyError::InvalidAddress(_))
        ));
        policy.members[0].addr_v4 = Some("198.18.0.255".parse().unwrap());
        assert!(matches!(
            policy.validate(),
            Err(RoutePolicyError::InvalidAddress(_))
        ));
        policy.members[0] = policy.members[1].clone();
        assert!(matches!(
            policy.validate(),
            Err(RoutePolicyError::DuplicateMember)
        ));
        policy.members.pop();
        policy.members[0].addr_v6 = Some("::ffff:198.18.0.2".parse().unwrap());
        assert!(matches!(
            policy.validate(),
            Err(RoutePolicyError::InvalidAddress(_))
        ));
        policy.members.clear();
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn malformed_or_noncanonical_snapshots_do_not_verify() {
        let algorithm = SignatureAlgorithm::Ed25519;
        let key = veil_crypto::generate_keypair(algorithm);
        let policy = sample();
        let authority = RoutePolicyAuthority {
            network_id: policy.network_id,
            algorithm,
            public_key: &key.public_key,
        };
        let mut blob = policy.encode_body(algorithm);
        let signature =
            veil_crypto::sign_message(algorithm, &key.public_key, &key.private_key, &blob).unwrap();
        blob.extend(signature);
        // The first member has a larger node ID than the second.
        assert!(matches!(
            verify_route_policy(&blob, &authority),
            Err(RoutePolicyError::Format)
        ));
        let signed =
            sign_route_policy(policy, algorithm, &key.public_key, &key.private_key).unwrap();
        for length in [
            0,
            DOMAIN.len(),
            HEADER_SIZE - 1,
            HEADER_SIZE,
            signed.len() - 1,
        ] {
            assert!(
                verify_route_policy(&signed[..length], &authority).is_err(),
                "length {length}"
            );
        }
    }
}
