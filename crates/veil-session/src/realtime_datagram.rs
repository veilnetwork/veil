//! Encrypted, loss-tolerant wire codec for realtime frames carried in QUIC
//! DATAGRAMs alongside an authenticated OVL1 session. The session runner
//! admits direct `AppRtData` and strictly canonical unacknowledged REALTIME
//! relay forwards; reliable delivery always remains on the ordered stream.
//!
//! The main session cipher uses an implicit ordered nonce counter and therefore
//! cannot be shared with an unordered/lossy lane. This module derives a
//! direction-specific sub-key from the already-authenticated session key and
//! uses an explicit packet sequence in every AEAD nonce. Frames larger than the
//! negotiated QUIC datagram ceiling are fragmented; loss expires only that
//! frame and never blocks later media.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};

const MAGIC: [u8; 4] = *b"VRT1";
const HEADER_LEN: usize = 24;
const TAG_LEN: usize = 16;
const MIN_DATAGRAM_LEN: usize = HEADER_LEN + TAG_LEN + 1;
const KDF_CONTEXT: &str = "veil/session/realtime-datagram/v1";

/// Realtime app/relay frames are capped well below the ordinary session ceiling.
pub const MAX_REALTIME_FRAME: usize = 16 * 1024;
/// A large batched media cell still fits without unbounded fragment fan-out.
pub const MAX_FRAGMENTS: usize = 32;
/// Incomplete messages retained per peer.
pub const MAX_ASSEMBLIES: usize = 64;
/// Aggregate authenticated plaintext retained by incomplete assemblies.
pub const MAX_ASSEMBLY_BYTES: usize = 512 * 1024;
/// Media older than this is stale and must never be replayed into playout.
pub const ASSEMBLY_TTL: Duration = Duration::from_secs(2);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RealtimeDatagramError {
    #[error("datagram ceiling {0} is too small")]
    DatagramTooSmall(usize),
    #[error("realtime frame length {0} is invalid")]
    FrameSize(usize),
    #[error("realtime frame requires {0} fragments")]
    TooManyFragments(usize),
    #[error("realtime datagram header is malformed")]
    Malformed,
    #[error("realtime datagram authentication failed")]
    Authentication,
    #[error("realtime datagram is replayed or outside the replay window")]
    Replay,
    #[error("realtime datagram sequence exhausted")]
    SequenceExhausted,
    #[error("realtime fragment metadata conflicts with its assembly")]
    AssemblyConflict,
    #[error("realtime fragment assembly exceeds its declared length")]
    AssemblyOverflow,
}

fn derive_key(raw_key: &[u8; 32], session_id: &[u8; 32]) -> [u8; 32] {
    let mut material = [0u8; 64];
    material[..32].copy_from_slice(raw_key);
    material[32..].copy_from_slice(session_id);
    let key = blake3::derive_key(KDF_CONTEXT, &material);
    use zeroize::Zeroize;
    material.zeroize();
    key
}

fn nonce_for(sequence: u64) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    nonce.into()
}

#[derive(Debug, Clone, Copy)]
struct FragmentHeader {
    message_id: u32,
    fragment_index: u16,
    fragment_count: u16,
    total_len: u32,
    sequence: u64,
}

impl FragmentHeader {
    fn encode(self) -> [u8; HEADER_LEN] {
        let mut bytes = [0u8; HEADER_LEN];
        bytes[..4].copy_from_slice(&MAGIC);
        bytes[4..8].copy_from_slice(&self.message_id.to_be_bytes());
        bytes[8..10].copy_from_slice(&self.fragment_index.to_be_bytes());
        bytes[10..12].copy_from_slice(&self.fragment_count.to_be_bytes());
        bytes[12..16].copy_from_slice(&self.total_len.to_be_bytes());
        bytes[16..24].copy_from_slice(&self.sequence.to_be_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, RealtimeDatagramError> {
        if bytes.len() < MIN_DATAGRAM_LEN || bytes[..4] != MAGIC {
            return Err(RealtimeDatagramError::Malformed);
        }
        let message_id = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        let fragment_index = u16::from_be_bytes(bytes[8..10].try_into().unwrap());
        let fragment_count = u16::from_be_bytes(bytes[10..12].try_into().unwrap());
        let total_len = u32::from_be_bytes(bytes[12..16].try_into().unwrap());
        let sequence = u64::from_be_bytes(bytes[16..24].try_into().unwrap());
        let total = total_len as usize;
        let count = fragment_count as usize;
        if message_id == 0
            || sequence == 0
            || total == 0
            || total > MAX_REALTIME_FRAME
            || count == 0
            || count > MAX_FRAGMENTS
            || fragment_index as usize >= count
        {
            return Err(RealtimeDatagramError::Malformed);
        }
        Ok(Self {
            message_id,
            fragment_index,
            fragment_count,
            total_len,
            sequence,
        })
    }
}

/// Send-side AEAD + sequence state for one session direction.
pub struct RealtimeDatagramTx {
    cipher: ChaCha20Poly1305,
    next_sequence: u64,
    next_message_id: u32,
}

impl RealtimeDatagramTx {
    pub fn new(raw_tx_key: &[u8; 32], session_id: &[u8; 32]) -> Self {
        let mut key = derive_key(raw_tx_key, session_id);
        let cipher = ChaCha20Poly1305::new((&key).into());
        use zeroize::Zeroize;
        key.zeroize();
        Self {
            cipher,
            next_sequence: 1,
            next_message_id: 1,
        }
    }

    /// Encrypt one complete loss-tolerant OVL1 frame into bounded datagrams.
    pub fn encode_frame(
        &mut self,
        frame: &[u8],
        max_datagram_size: usize,
    ) -> Result<Vec<Vec<u8>>, RealtimeDatagramError> {
        if frame.is_empty() || frame.len() > MAX_REALTIME_FRAME {
            return Err(RealtimeDatagramError::FrameSize(frame.len()));
        }
        let max_plaintext = max_datagram_size
            .checked_sub(HEADER_LEN + TAG_LEN)
            .filter(|size| *size > 0)
            .ok_or(RealtimeDatagramError::DatagramTooSmall(max_datagram_size))?;
        let fragment_count = frame.len().div_ceil(max_plaintext);
        if fragment_count > MAX_FRAGMENTS {
            return Err(RealtimeDatagramError::TooManyFragments(fragment_count));
        }
        let message_id = self.next_message_id;
        self.next_message_id = self.next_message_id.wrapping_add(1);
        if self.next_message_id == 0 {
            self.next_message_id = 1;
        }

        let mut encoded = Vec::with_capacity(fragment_count);
        for (index, chunk) in frame.chunks(max_plaintext).enumerate() {
            let sequence = self.next_sequence;
            self.next_sequence = self
                .next_sequence
                .checked_add(1)
                .ok_or(RealtimeDatagramError::SequenceExhausted)?;
            let header = FragmentHeader {
                message_id,
                fragment_index: index as u16,
                fragment_count: fragment_count as u16,
                total_len: frame.len() as u32,
                sequence,
            }
            .encode();
            let ciphertext = self
                .cipher
                .encrypt(
                    &nonce_for(sequence),
                    Payload {
                        msg: chunk,
                        aad: &header,
                    },
                )
                .map_err(|_| RealtimeDatagramError::Authentication)?;
            let mut datagram = Vec::with_capacity(header.len() + ciphertext.len());
            datagram.extend_from_slice(&header);
            datagram.extend_from_slice(&ciphertext);
            debug_assert!(datagram.len() <= max_datagram_size);
            encoded.push(datagram);
        }
        Ok(encoded)
    }
}

#[derive(Default)]
struct ReplayWindow {
    highest: u64,
    bitmap: u128,
}

impl ReplayWindow {
    fn precheck(&self, sequence: u64) -> Result<(), RealtimeDatagramError> {
        if sequence == 0 {
            return Err(RealtimeDatagramError::Malformed);
        }
        if sequence > self.highest {
            return Ok(());
        }
        let delta = self.highest - sequence;
        if delta >= u128::BITS as u64 || self.bitmap & (1u128 << delta) != 0 {
            return Err(RealtimeDatagramError::Replay);
        }
        Ok(())
    }

    /// Commit only after AEAD verification, so forged high sequences cannot
    /// advance the window and suppress later legitimate media.
    fn commit(&mut self, sequence: u64) {
        if sequence > self.highest {
            let shift = sequence - self.highest;
            self.bitmap = if shift >= u128::BITS as u64 {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.highest = sequence;
        } else {
            self.bitmap |= 1u128 << (self.highest - sequence);
        }
    }
}

struct Assembly {
    created_at: Instant,
    total_len: usize,
    fragments: Vec<Option<Vec<u8>>>,
    stored_bytes: usize,
}

/// Receive-side AEAD, replay window and bounded fragment reassembly.
pub struct RealtimeDatagramRx {
    cipher: ChaCha20Poly1305,
    replay: ReplayWindow,
    assemblies: HashMap<u32, Assembly>,
    assembly_bytes: usize,
}

impl RealtimeDatagramRx {
    pub fn new(raw_rx_key: &[u8; 32], session_id: &[u8; 32]) -> Self {
        let mut key = derive_key(raw_rx_key, session_id);
        let cipher = ChaCha20Poly1305::new((&key).into());
        use zeroize::Zeroize;
        key.zeroize();
        Self {
            cipher,
            replay: ReplayWindow::default(),
            assemblies: HashMap::new(),
            assembly_bytes: 0,
        }
    }

    /// Authenticate one fragment. Returns a complete frame only when every
    /// fragment arrived; incomplete/lost messages remain bounded and expire.
    pub fn decode_datagram(
        &mut self,
        datagram: &[u8],
        now: Instant,
    ) -> Result<Option<Vec<u8>>, RealtimeDatagramError> {
        self.prune(now);
        let header = FragmentHeader::decode(datagram)?;
        self.replay.precheck(header.sequence)?;
        let plaintext = self
            .cipher
            .decrypt(
                &nonce_for(header.sequence),
                Payload {
                    msg: &datagram[HEADER_LEN..],
                    aad: &datagram[..HEADER_LEN],
                },
            )
            .map_err(|_| RealtimeDatagramError::Authentication)?;
        self.replay.commit(header.sequence);
        if plaintext.is_empty() || plaintext.len() > header.total_len as usize {
            return Err(RealtimeDatagramError::AssemblyOverflow);
        }

        let fragment_count = header.fragment_count as usize;
        let total_len = header.total_len as usize;
        if let Some(existing) = self.assemblies.get(&header.message_id)
            && (existing.total_len != total_len || existing.fragments.len() != fragment_count)
        {
            self.remove_assembly(header.message_id);
            return Err(RealtimeDatagramError::AssemblyConflict);
        }
        if !self.assemblies.contains_key(&header.message_id) {
            self.make_room(None, plaintext.len(), true);
            self.assemblies.insert(
                header.message_id,
                Assembly {
                    created_at: now,
                    total_len,
                    fragments: (0..fragment_count).map(|_| None).collect(),
                    stored_bytes: 0,
                },
            );
        }

        // A message can grow one fragment at a time after its assembly was
        // admitted. Enforce the aggregate byte cap on EVERY insertion, not
        // just the first fragment; evict older unrelated assemblies while
        // preserving the one currently being completed.
        if self.assemblies[&header.message_id].fragments[header.fragment_index as usize].is_some() {
            // Same authenticated fragment under a fresh sequence is still a
            // semantic duplicate. Consume its sequence but retain one copy.
            return Ok(None);
        }
        self.make_room(Some(header.message_id), plaintext.len(), false);

        let assembly = self
            .assemblies
            .get_mut(&header.message_id)
            .expect("assembly inserted above");
        let slot = &mut assembly.fragments[header.fragment_index as usize];
        if assembly.stored_bytes.saturating_add(plaintext.len()) > assembly.total_len {
            self.remove_assembly(header.message_id);
            return Err(RealtimeDatagramError::AssemblyOverflow);
        }
        assembly.stored_bytes += plaintext.len();
        self.assembly_bytes += plaintext.len();
        *slot = Some(plaintext);

        if assembly.fragments.iter().any(Option::is_none) {
            return Ok(None);
        }
        if assembly.stored_bytes != assembly.total_len {
            self.remove_assembly(header.message_id);
            return Err(RealtimeDatagramError::AssemblyOverflow);
        }
        let mut complete = Vec::with_capacity(assembly.total_len);
        for fragment in &mut assembly.fragments {
            complete.extend(fragment.take().expect("all fragments checked"));
        }
        self.remove_assembly(header.message_id);
        Ok(Some(complete))
    }

    fn prune(&mut self, now: Instant) {
        let expired: Vec<u32> = self
            .assemblies
            .iter()
            .filter_map(|(&id, assembly)| {
                (now.saturating_duration_since(assembly.created_at) >= ASSEMBLY_TTL).then_some(id)
            })
            .collect();
        for id in expired {
            self.remove_assembly(id);
        }
    }

    fn make_room(&mut self, protected: Option<u32>, incoming: usize, is_new: bool) {
        while (is_new && self.assemblies.len() >= MAX_ASSEMBLIES)
            || self.assembly_bytes.saturating_add(incoming) > MAX_ASSEMBLY_BYTES
        {
            let Some(oldest) = self
                .assemblies
                .iter()
                .filter(|(id, _)| Some(**id) != protected)
                .min_by_key(|(_, assembly)| assembly.created_at)
                .map(|(&id, _)| id)
            else {
                break;
            };
            self.remove_assembly(oldest);
        }
    }

    fn remove_assembly(&mut self, message_id: u32) {
        if let Some(assembly) = self.assemblies.remove(&message_id) {
            self.assembly_bytes = self.assembly_bytes.saturating_sub(assembly.stored_bytes);
        }
    }

    #[cfg(test)]
    fn retained(&self) -> (usize, usize) {
        (self.assemblies.len(), self.assembly_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (RealtimeDatagramTx, RealtimeDatagramRx) {
        let key = [0x42; 32];
        let session = [0x24; 32];
        (
            RealtimeDatagramTx::new(&key, &session),
            RealtimeDatagramRx::new(&key, &session),
        )
    }

    #[test]
    fn fragmented_frame_survives_out_of_order_delivery() {
        let (mut tx, mut rx) = pair();
        let frame: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let mut datagrams = tx.encode_frame(&frame, 256).unwrap();
        assert!(datagrams.len() > 1);
        datagrams.reverse();
        let now = Instant::now();
        let mut complete = None;
        for datagram in datagrams {
            if let Some(frame) = rx.decode_datagram(&datagram, now).unwrap() {
                complete = Some(frame);
            }
        }
        assert_eq!(complete.as_deref(), Some(frame.as_slice()));
        assert_eq!(rx.retained(), (0, 0));
    }

    #[test]
    fn replay_and_tamper_are_rejected_without_poisoning_window() {
        let (mut tx, mut rx) = pair();
        let datagram = tx.encode_frame(b"first", 1200).unwrap().remove(0);
        let now = Instant::now();
        assert_eq!(
            rx.decode_datagram(&datagram, now).unwrap(),
            Some(b"first".to_vec())
        );
        assert_eq!(
            rx.decode_datagram(&datagram, now),
            Err(RealtimeDatagramError::Replay)
        );

        let mut second = tx.encode_frame(b"second", 1200).unwrap().remove(0);
        second[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(
            rx.decode_datagram(&second, now),
            Err(RealtimeDatagramError::Authentication)
        );
        let second = tx.encode_frame(b"third", 1200).unwrap().remove(0);
        assert_eq!(
            rx.decode_datagram(&second, now).unwrap(),
            Some(b"third".to_vec())
        );
    }

    #[test]
    fn incomplete_frame_expires_and_bounds_are_enforced() {
        let (mut tx, mut rx) = pair();
        let frame = vec![7u8; 2048];
        let datagrams = tx.encode_frame(&frame, 128).unwrap();
        assert!(
            rx.decode_datagram(&datagrams[0], Instant::now())
                .unwrap()
                .is_none()
        );
        assert_eq!(rx.retained().0, 1);
        let later = Instant::now() + ASSEMBLY_TTL + Duration::from_millis(1);
        let next = tx.encode_frame(b"next", 128).unwrap().remove(0);
        assert_eq!(
            rx.decode_datagram(&next, later).unwrap(),
            Some(b"next".to_vec())
        );
        assert_eq!(rx.retained(), (0, 0));
        assert_eq!(
            tx.encode_frame(&vec![0u8; MAX_REALTIME_FRAME + 1], 1200),
            Err(RealtimeDatagramError::FrameSize(MAX_REALTIME_FRAME + 1))
        );
        assert_eq!(
            tx.encode_frame(b"x", HEADER_LEN + TAG_LEN),
            Err(RealtimeDatagramError::DatagramTooSmall(
                HEADER_LEN + TAG_LEN
            ))
        );
    }

    #[test]
    fn aggregate_cap_is_enforced_as_existing_assemblies_grow() {
        let (mut tx, mut rx) = pair();
        let now = Instant::now();
        let mut pending = Vec::new();
        for i in 0..MAX_ASSEMBLIES {
            let frame = vec![i as u8; MAX_REALTIME_FRAME];
            let datagrams = tx.encode_frame(&frame, 4200).unwrap();
            assert!(datagrams.len() > 2);
            assert!(rx.decode_datagram(&datagrams[0], now).unwrap().is_none());
            pending.push(datagrams);
        }
        assert_eq!(rx.retained().0, MAX_ASSEMBLIES);
        assert!(rx.retained().1 < MAX_ASSEMBLY_BYTES);

        // Growing already-admitted assemblies used to bypass the aggregate
        // byte cap. Feeding each second fragment must evict old assemblies as
        // needed while never retaining more than the configured ceiling.
        for datagrams in pending {
            let _ = rx.decode_datagram(&datagrams[1], now);
            let (assemblies, bytes) = rx.retained();
            assert!(assemblies <= MAX_ASSEMBLIES);
            assert!(bytes <= MAX_ASSEMBLY_BYTES);
        }
    }

    #[test]
    fn wrong_direction_key_cannot_decrypt() {
        let session = [9u8; 32];
        let mut tx = RealtimeDatagramTx::new(&[1u8; 32], &session);
        let mut rx = RealtimeDatagramRx::new(&[2u8; 32], &session);
        let datagram = tx.encode_frame(b"secret", 1200).unwrap().remove(0);
        assert_eq!(
            rx.decode_datagram(&datagram, Instant::now()),
            Err(RealtimeDatagramError::Authentication)
        );
    }
}
