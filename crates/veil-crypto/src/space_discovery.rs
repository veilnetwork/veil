//! Self-authenticating, bounded DHT carrier for public Space discovery.
//!
//! The application payload remains opaque to the transport and is verified by
//! xVeil as a `SpacePublicDescriptor` plus holder attestation. This outer
//! record gives the DHT a security boundary it can enforce without learning
//! Space control state: canonical route key, holder/node-id binding, Ed25519
//! signature, short expiry and a hard payload cap.

use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub const SPACE_DISCOVERY_DHT_MAGIC: [u8; 2] = *b"XS";
pub const SPACE_DISCOVERY_RECORD_VERSION: u8 = 1;
pub const MAX_SPACE_DISCOVERY_PAYLOAD: usize = 16 * 1024;
pub const MAX_SPACE_DISCOVERY_LIFETIME_MILLIS: u64 = 2 * 60 * 60 * 1_000;
pub const SPACE_DISCOVERY_CLOCK_SKEW_MILLIS: u64 = 5 * 60 * 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpaceDiscoveryRoute {
    /// Exact lookup by Space id.
    Direct([u8; 32]),
    /// Lookup by an application-normalized search-token hash.
    Search([u8; 32]),
}

impl SpaceDiscoveryRoute {
    fn tag(self) -> u8 {
        match self {
            Self::Direct(_) => 0,
            Self::Search(_) => 1,
        }
    }

    fn body(self) -> [u8; 32] {
        match self {
            Self::Direct(value) | Self::Search(value) => value,
        }
    }

    fn from_parts(tag: u8, body: [u8; 32]) -> Option<Self> {
        match tag {
            0 => Some(Self::Direct(body)),
            1 => Some(Self::Search(body)),
            _ => None,
        }
    }

    pub fn dht_key(self) -> [u8; 32] {
        let mut hash = Hasher::new();
        match self {
            Self::Direct(_) => hash.update(b"veil.space-discovery.direct.v1"),
            Self::Search(_) => hash.update(b"veil.space-discovery.search.v1"),
        };
        hash.update(&self.body());
        *hash.finalize().as_bytes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpaceDiscoveryError {
    Unsupported,
    BadRoute,
    BadLifetime,
    Expired,
    BadPayload,
    HolderMismatch,
    BadSignature,
}

/// One short-lived DHT sample. `payload` is the strict application record;
/// `signature` covers [`Self::canonical_bytes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceDiscoveryRecord {
    pub version: u8,
    pub route: SpaceDiscoveryRoute,
    pub space_id: [u8; 32],
    pub holder_node_id: [u8; 32],
    pub holder_sign_pk: [u8; 32],
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub payload: Vec<u8>,
    pub signature: [u8; 64],
}

impl SpaceDiscoveryRecord {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 1 + 32 * 4 + 8 * 2 + 4 + self.payload.len());
        out.push(self.version);
        out.push(self.route.tag());
        out.extend_from_slice(&self.route.body());
        out.extend_from_slice(&self.space_id);
        out.extend_from_slice(&self.holder_node_id);
        out.extend_from_slice(&self.holder_sign_pk);
        out.extend_from_slice(&self.issued_at_unix_ms.to_le_bytes());
        out.extend_from_slice(&self.expires_at_unix_ms.to_le_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.canonical_bytes().len() + 64);
        out.extend_from_slice(&SPACE_DISCOVERY_DHT_MAGIC);
        out.extend_from_slice(&self.canonical_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut reader = Reader { bytes, offset: 0 };
        if reader.take(2)? != SPACE_DISCOVERY_DHT_MAGIC {
            return None;
        }
        let version = reader.u8()?;
        let route = SpaceDiscoveryRoute::from_parts(reader.u8()?, reader.arr32()?)?;
        let space_id = reader.arr32()?;
        let holder_node_id = reader.arr32()?;
        let holder_sign_pk = reader.arr32()?;
        let issued_at_unix_ms = reader.u64()?;
        let expires_at_unix_ms = reader.u64()?;
        let payload_len = reader.u32()? as usize;
        if payload_len == 0 || payload_len > MAX_SPACE_DISCOVERY_PAYLOAD {
            return None;
        }
        let payload = reader.take(payload_len)?.to_vec();
        let signature = reader.arr64()?;
        if reader.offset != bytes.len() {
            return None;
        }
        Some(Self {
            version,
            route,
            space_id,
            holder_node_id,
            holder_sign_pk,
            issued_at_unix_ms,
            expires_at_unix_ms,
            payload,
            signature,
        })
    }

    pub fn sign(
        route: SpaceDiscoveryRoute,
        space_id: [u8; 32],
        holder_key: &SigningKey,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
        payload: Vec<u8>,
    ) -> Self {
        let holder_sign_pk = holder_key.verifying_key().to_bytes();
        let holder_node_id = *blake3::hash(&holder_sign_pk).as_bytes();
        let mut record = Self {
            version: SPACE_DISCOVERY_RECORD_VERSION,
            route,
            space_id,
            holder_node_id,
            holder_sign_pk,
            issued_at_unix_ms,
            expires_at_unix_ms,
            payload,
            signature: [0; 64],
        };
        record.signature = holder_key.sign(&record.canonical_bytes()).to_bytes();
        record
    }

    pub fn verify_at(&self, now_unix_ms: u64) -> Result<(), SpaceDiscoveryError> {
        if self.version != SPACE_DISCOVERY_RECORD_VERSION {
            return Err(SpaceDiscoveryError::Unsupported);
        }
        if matches!(self.route, SpaceDiscoveryRoute::Direct(id) if id != self.space_id) {
            return Err(SpaceDiscoveryError::BadRoute);
        }
        if self.payload.is_empty() || self.payload.len() > MAX_SPACE_DISCOVERY_PAYLOAD {
            return Err(SpaceDiscoveryError::BadPayload);
        }
        if self.expires_at_unix_ms <= self.issued_at_unix_ms
            || self.expires_at_unix_ms - self.issued_at_unix_ms
                > MAX_SPACE_DISCOVERY_LIFETIME_MILLIS
            || self.issued_at_unix_ms
                > now_unix_ms.saturating_add(SPACE_DISCOVERY_CLOCK_SKEW_MILLIS)
        {
            return Err(SpaceDiscoveryError::BadLifetime);
        }
        if self.expires_at_unix_ms <= now_unix_ms {
            return Err(SpaceDiscoveryError::Expired);
        }
        if *blake3::hash(&self.holder_sign_pk).as_bytes() != self.holder_node_id {
            return Err(SpaceDiscoveryError::HolderMismatch);
        }
        let verifying_key = VerifyingKey::from_bytes(&self.holder_sign_pk)
            .map_err(|_| SpaceDiscoveryError::BadSignature)?;
        verifying_key
            .verify(
                &self.canonical_bytes(),
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| SpaceDiscoveryError::BadSignature)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpaceDiscoveryStoreDecision {
    Accept,
    RejectKeepExisting,
    RejectInvalid,
}

/// Bounded multi-writer sampling for one search-token key.
///
/// One DHT shard stores one value, while a contested lookup reads K replicas.
/// Different replicas therefore use their own node id as the rendezvous salt:
/// they retain different deterministic samples instead of every replica being
/// overwritten by the same last writer. A refresh from the same holder for the
/// same Space always replaces its older sample.
pub fn space_discovery_store_decision(
    existing: Option<&[u8]>,
    incoming: &[u8],
    now_unix_ms: u64,
    local_node_id: &[u8; 32],
) -> SpaceDiscoveryStoreDecision {
    let Some(candidate) = SpaceDiscoveryRecord::from_bytes(incoming) else {
        return SpaceDiscoveryStoreDecision::RejectInvalid;
    };
    if candidate.verify_at(now_unix_ms).is_err() {
        return SpaceDiscoveryStoreDecision::RejectInvalid;
    }
    let incumbent = existing
        .and_then(SpaceDiscoveryRecord::from_bytes)
        .filter(|value| value.verify_at(now_unix_ms).is_ok())
        .filter(|value| value.route == candidate.route);
    let Some(incumbent) = incumbent else {
        return SpaceDiscoveryStoreDecision::Accept;
    };
    if incumbent.space_id == candidate.space_id
        && incumbent.holder_node_id == candidate.holder_node_id
    {
        return if candidate.issued_at_unix_ms > incumbent.issued_at_unix_ms {
            SpaceDiscoveryStoreDecision::Accept
        } else {
            SpaceDiscoveryStoreDecision::RejectKeepExisting
        };
    }
    let candidate_rank = sample_rank(local_node_id, &candidate);
    let incumbent_rank = sample_rank(local_node_id, &incumbent);
    if candidate_rank < incumbent_rank {
        SpaceDiscoveryStoreDecision::Accept
    } else {
        SpaceDiscoveryStoreDecision::RejectKeepExisting
    }
}

fn sample_rank(local_node_id: &[u8; 32], record: &SpaceDiscoveryRecord) -> [u8; 32] {
    let mut hash = Hasher::new();
    hash.update(b"veil.space-discovery.sample.v1");
    hash.update(local_node_id);
    hash.update(&record.space_id);
    hash.update(&record.holder_node_id);
    *hash.finalize().as_bytes()
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Reader<'_> {
    fn take(&mut self, length: usize) -> Option<&[u8]> {
        let end = self.offset.checked_add(length)?;
        let result = self.bytes.get(self.offset..end)?;
        self.offset = end;
        Some(result)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    fn arr32(&mut self) -> Option<[u8; 32]> {
        self.take(32)?.try_into().ok()
    }

    fn arr64(&mut self) -> Option<[u8; 64]> {
        self.take(64)?.try_into().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn record(
        route: SpaceDiscoveryRoute,
        space: [u8; 32],
        holder_seed: u8,
        issued: u64,
    ) -> SpaceDiscoveryRecord {
        SpaceDiscoveryRecord::sign(
            route,
            space,
            &key(holder_seed),
            issued,
            issued + 3_600_000,
            br#"{"descriptor":"strict-app-payload"}"#.to_vec(),
        )
    }

    #[test]
    fn signed_record_round_trips_and_binds_direct_route() {
        let space = [7; 32];
        let record = record(SpaceDiscoveryRoute::Direct(space), space, 3, 1000);
        assert_eq!(record.verify_at(1001), Ok(()));
        assert_eq!(
            SpaceDiscoveryRecord::from_bytes(&record.to_bytes()),
            Some(record.clone())
        );
        assert_eq!(
            record.route.dht_key(),
            SpaceDiscoveryRoute::Direct(space).dht_key()
        );

        let mut wrong_route = record;
        wrong_route.route = SpaceDiscoveryRoute::Direct([8; 32]);
        assert_eq!(
            wrong_route.verify_at(1001),
            Err(SpaceDiscoveryError::BadRoute)
        );
    }

    #[test]
    fn verification_rejects_tamper_expiry_oversize_and_trailing_bytes() {
        let space = [7; 32];
        let record = record(SpaceDiscoveryRoute::Search([9; 32]), space, 4, 2000);
        let mut tampered = record.clone();
        tampered.payload[0] ^= 1;
        assert_eq!(
            tampered.verify_at(2001),
            Err(SpaceDiscoveryError::BadSignature)
        );
        assert_eq!(
            record.verify_at(3_602_000),
            Err(SpaceDiscoveryError::Expired)
        );

        let oversized = SpaceDiscoveryRecord::sign(
            SpaceDiscoveryRoute::Search([9; 32]),
            space,
            &key(4),
            2000,
            3000,
            vec![0; MAX_SPACE_DISCOVERY_PAYLOAD + 1],
        );
        assert_eq!(
            oversized.verify_at(2001),
            Err(SpaceDiscoveryError::BadPayload)
        );
        assert!(SpaceDiscoveryRecord::from_bytes(&oversized.to_bytes()).is_none());

        let mut trailing = record.to_bytes();
        trailing.push(0);
        assert!(SpaceDiscoveryRecord::from_bytes(&trailing).is_none());
    }

    #[test]
    fn store_refreshes_same_holder_and_samples_competing_records() {
        let route = SpaceDiscoveryRoute::Search([5; 32]);
        let old = record(route, [1; 32], 1, 3000);
        let fresh = record(route, [1; 32], 1, 3001);
        assert_eq!(
            space_discovery_store_decision(
                Some(&old.to_bytes()),
                &fresh.to_bytes(),
                3002,
                &[9; 32],
            ),
            SpaceDiscoveryStoreDecision::Accept
        );
        assert_eq!(
            space_discovery_store_decision(
                Some(&fresh.to_bytes()),
                &old.to_bytes(),
                3002,
                &[9; 32],
            ),
            SpaceDiscoveryStoreDecision::RejectKeepExisting
        );

        let competing = record(route, [2; 32], 2, 3001);
        let left = space_discovery_store_decision(
            Some(&fresh.to_bytes()),
            &competing.to_bytes(),
            3002,
            &[9; 32],
        );
        let right = space_discovery_store_decision(
            Some(&competing.to_bytes()),
            &fresh.to_bytes(),
            3002,
            &[9; 32],
        );
        assert_ne!(left, right);
    }
}
