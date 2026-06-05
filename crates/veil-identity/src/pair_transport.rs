//! Async transport drivers for the pairing ceremony.
//!
//! The state machines [`super::pair_runtime`] are transport-
//! agnostic — they consume `&[u8]` and produce `Vec<u8>`. This
//! module wires them to any `AsyncRead + AsyncWrite` pair via a
//! trivial length-prefixed framing:
//!
//! ```text
//! frame = u32-be length || body
//! ```
//!
//! The pairing ceremony only exchanges three frames, so we don't
//! need the full OVL1 session framer — a dedicated codec keeps
//! the dial-back flow self-contained and independent of the main
//! session runtime. Callers are expected to provide a freshly
//! connected TCP stream (or `tokio::io::duplex` half in tests).
//!
//! # Cancellation
//!
//! The drivers are single-shot: they consume exactly the number of
//! frames the ceremony requires (2 on source, 3 read / 2 written
//! on target) and return. Dropping the future mid-flight aborts
//! cleanly — no persistent state is mutated until the final
//! return. Partial writes leave the stream in an undefined state
//! (caller should close the connection on error).

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::pair_runtime::{PairCeremonyError, PairingSource, PairingTarget, SourceConfirmOutcome};
use veil_proto::identity_document::IdentityDocument;
use veil_proto::pair_session::{MAX_PAIR_CERT_DOC_SIZE, PAIR_HELLO_SIZE};

/// Hard cap on a single frame's body length. Sized to fit the
/// largest frame (Cert = 39 B header + up to 8 KiB document) plus
/// a generous safety margin. A too-strict cap here would
/// artificially constrain document growth.
pub const MAX_PAIR_FRAME_BODY: usize = MAX_PAIR_CERT_DOC_SIZE + 512;

// Cap must admit the smallest frame (Hello) — sanity assert so a
// future tweak of `MAX_PAIR_CERT_DOC_SIZE` can't regress us.
const _: () = assert!(MAX_PAIR_FRAME_BODY >= PAIR_HELLO_SIZE);

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum PairTransportError {
    #[error("pair transport: i/o: {0}")]
    Io(#[from] io::Error),
    #[error("pair transport: declared frame {got} B exceeds cap {MAX_PAIR_FRAME_BODY} B")]
    FrameOversized { got: u32 },
    #[error("pair transport: ceremony: {0}")]
    Ceremony(#[from] PairCeremonyError),
    /// Target's user pressed "codes don't match" — ceremony
    /// completed cryptographically but the local operator
    /// explicitly rejected the OOB compare.
    #[error("pair transport: target-side operator aborted (OOB mismatch)")]
    TargetAborted,
    /// Source's user pressed "codes don't match" — source's
    /// operator rejected the OOB compare after sending Cert.
    /// The appended `IdentityKey` in the working doc must NOT be
    /// persisted.
    #[error("pair transport: source-side operator aborted (OOB mismatch)")]
    SourceAborted,
}

// ── Framing ──────────────────────────────────────────────────────────────────

/// Read a single length-prefixed frame from `r`. Enforces
/// [`MAX_PAIR_FRAME_BODY`] so a malicious peer can't force us
/// to allocate unbounded memory.
pub async fn read_frame<R>(r: &mut R) -> Result<Vec<u8>, PairTransportError>
where
    R: AsyncRead + Unpin,
{
    let len = r.read_u32().await?;
    if (len as usize) > MAX_PAIR_FRAME_BODY {
        return Err(PairTransportError::FrameOversized { got: len });
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).await?;
    Ok(body)
}

/// Write a single length-prefixed frame to `w`.
///
/// Audit batch 2026-05-25 phase M (cross-audit closure): previously
/// guarded by а `debug_assert!` which is stripped в release builds.
/// А mis-built caller passing а body > `MAX_PAIR_FRAME_BODY` would
/// silently put an oversized frame on the wire — readers would
/// reject с `FrameOversized` but only after the bytes already went
/// out, и в the case of streaming senders the local buffer might
/// reallocate к multi-MiB before the peer closes.  Convert к а
/// proper runtime check that returns the existing `FrameOversized`
/// variant so callers handle it through the normal `?` path.
pub async fn write_frame<W>(w: &mut W, body: &[u8]) -> Result<(), PairTransportError>
where
    W: AsyncWrite + Unpin,
{
    if body.len() > MAX_PAIR_FRAME_BODY {
        return Err(PairTransportError::FrameOversized {
            got: body.len().try_into().unwrap_or(u32::MAX),
        });
    }
    w.write_u32(body.len() as u32).await?;
    w.write_all(body).await?;
    w.flush().await?;
    Ok(())
}

// ── Source driver ────────────────────────────────────────────────────────────

/// Outcome returned by [`run_pair_source`] on a fully-confirmed
/// ceremony.
#[derive(Debug)]
pub struct SourceTransportOutcome {
    /// Updated document with the target's `IdentityKey` appended
    /// and re-signed. Caller persists + republishes.
    pub finalized_document: IdentityDocument,
    /// 6-digit OOB code the source displayed (logged for audit).
    pub oob_code: String,
    /// Index of the freshly-appended `IdentityKey` inside the
    /// finalized document.
    pub appended_identity_key_idx: u16,
}

/// Run the source side of the ceremony over a connected stream.
///
/// Sequence:
///
/// 1. **Read Hello** from target.
/// 2. **Compute Cert + OOB** [`PairingSource::handle_hello`].
/// 3. **Write Cert** back to target.
/// 4. **Invoke `oob_confirm(oob_code)`** — caller prompts the
///    source-side operator ("does the target screen show
///    `XXX-YYY`?"). On `false`, we still consume the target's
///    Confirm (so the target's state machine finishes cleanly)
///    then surface [`PairTransportError::SourceAborted`] — the
///    caller must NOT persist.
/// 5. **Read Confirm** from target. If target says `confirmed =
/// false`, return [`PairTransportError::TargetAborted`].
/// 6. **Return** the finalized document to the caller for
///    persistence + DHT republish.
pub async fn run_pair_source<S, F>(
    source: &mut PairingSource,
    stream: &mut S,
    oob_confirm: F,
) -> Result<SourceTransportOutcome, PairTransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(&str) -> bool,
{
    // 1. Hello.
    let hello_bytes = read_frame(stream).await?;

    // 2. Handle Hello → Cert + OOB.
    let hello_outcome = source.handle_hello(&hello_bytes)?;

    // 3. Send Cert.
    write_frame(stream, &hello_outcome.cert_bytes).await?;

    // 4. Ask the source's operator. Doing this *after* Cert is
    // sent keeps the protocol lock-step — target's OOB depends
    // on the source_ephemeral_pk we just committed to.
    let local_ok = oob_confirm(&hello_outcome.oob_code);

    // 5. Read + validate Confirm regardless of the local decision
    // so the target's state machine observes the same wire
    // shape whether we abort or succeed. `handle_confirm`
    // with `confirmed=false` returns `UserAborted`.
    let confirm_bytes = read_frame(stream).await?;
    let finalize: Result<SourceConfirmOutcome, PairCeremonyError> =
        source.handle_confirm(&confirm_bytes);

    match (local_ok, finalize) {
        (true, Ok(outcome)) => Ok(SourceTransportOutcome {
            finalized_document: outcome.finalized_document,
            oob_code: hello_outcome.oob_code,
            appended_identity_key_idx: hello_outcome.appended_identity_key_idx,
        }),
        (false, _) => Err(PairTransportError::SourceAborted),
        (_, Err(PairCeremonyError::UserAborted)) => Err(PairTransportError::TargetAborted),
        (_, Err(e)) => Err(PairTransportError::Ceremony(e)),
    }
}

// ── Target driver ────────────────────────────────────────────────────────────

/// Outcome returned by [`run_pair_target`] on a fully-confirmed
/// ceremony.
#[derive(Debug)]
pub struct TargetTransportOutcome {
    /// The fully-signed identity document the target just
    /// received. Caller persists as the target's local view of
    /// the identity.
    pub document: IdentityDocument,
    /// 6-digit OOB code target displayed (logged for audit).
    pub oob_code: String,
    /// Index at which target's own `IdentityKey` landed.
    pub target_identity_key_idx: u16,
    /// Target's freshly-minted 32-byte identity_sk seed. Caller
    /// persists via `save_identity_sk` so the target can sign
    /// outbound frames under the paired identity.
    pub target_identity_sk_seed: [u8; 32],
    /// Target's freshly-minted 16-byte per-device instance tag.
    pub target_instance_id: [u8; 16],
}

/// Run the target side of the ceremony over a connected stream.
///
/// Sequence:
///
/// 1. **Build + write Hello.**
/// 2. **Read Cert** from source.
/// 3. **Compute OOB** [`PairingTarget::handle_cert`].
/// 4. **Invoke `oob_confirm(oob_code)`** — caller prompts target
///    operator. On `false` we send a `confirmed = false` Confirm
///    (so source learns the rejection) and surface
///    [`PairTransportError::TargetAborted`].
/// 5. **Build + write Confirm** with the user's decision.
/// 6. **Return** on success.
pub async fn run_pair_target<S, F>(
    target: &mut PairingTarget,
    stream: &mut S,
    oob_confirm: F,
) -> Result<TargetTransportOutcome, PairTransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(&str) -> bool,
{
    // 1. Hello.
    let hello_bytes = target.build_hello()?;
    write_frame(stream, &hello_bytes).await?;

    // 2. Read Cert.
    let cert_bytes = read_frame(stream).await?;

    // 3. Derive OOB + locate target's IdentityKey slot.
    let cert_outcome = target.handle_cert(&cert_bytes)?;

    // 4. Ask the target's operator.
    let local_ok = oob_confirm(&cert_outcome.oob_code);

    // 5. Confirm goes back either way so source observes a
    // well-formed frame — otherwise source would sit on
    // `read_frame` until TCP timeout.
    let confirm_bytes = target.build_confirm(local_ok)?;
    write_frame(stream, &confirm_bytes).await?;

    if !local_ok {
        return Err(PairTransportError::TargetAborted);
    }

    // 6. Pull the finalized doc + sk material out of the state
    // machine. We've just finished the last write so the state
    // machine is in `Finished` and these fields are stable.
    let doc = target
        .document()
        .expect("document set during handle_cert")
        .clone();
    Ok(TargetTransportOutcome {
        document: doc,
        oob_code: cert_outcome.oob_code,
        target_identity_key_idx: cert_outcome.target_identity_key_idx,
        target_identity_sk_seed: *target.target_identity_sk_seed(),
        target_instance_id: *target.target_instance_id(),
    })
}

// ── TCP convenience wrappers ─────────────────────────────────────────────────

/// Source-side TCP wrapper: bind `host_port`, accept one
/// connection, run the ceremony. Used by `identity pair-listen`
/// and by integration tests. Caller supplies the `PairingSource`
/// state (already seeded with loaded keys + document).
///
/// The `oob_confirm` closure runs once the source has sent the
/// Cert frame — typical UIs prompt the operator at that point.
pub async fn run_pair_source_tcp<F>(
    host_port: &str,
    source: &mut super::pair_runtime::PairingSource,
    oob_confirm: F,
) -> Result<SourceTransportOutcome, PairTransportError>
where
    F: FnOnce(&str) -> bool,
{
    let listener = tokio::net::TcpListener::bind(host_port).await?;
    let (mut stream, _peer) = listener.accept().await?;
    run_pair_source(source, &mut stream, oob_confirm).await
}

/// Target-side TCP wrapper: dial `host_port`, run the ceremony.
/// Used by `identity pair-accept` and by integration tests.
pub async fn run_pair_target_tcp<F>(
    host_port: &str,
    target: &mut super::pair_runtime::PairingTarget,
    oob_confirm: F,
) -> Result<TargetTransportOutcome, PairTransportError>
where
    F: FnOnce(&str) -> bool,
{
    let mut stream = tokio::net::TcpStream::connect(host_port).await?;
    run_pair_target(target, &mut stream, oob_confirm).await
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    use crate::sovereign::SovereignIdentity;
    use crate::sovereign_flow::{CreateIdentityOptions, create_identity, load_identity_sk};
    use veil_crypto::identity::derive_master_sk_ed25519;
    use veil_proto::pairing_invite::PairingUri;

    struct Ctx {
        sov: SovereignIdentity,
        master_sk: SigningKey,
        identity_sk: SigningKey,
    }

    fn provision() -> Ctx {
        let dir = crate::test_support::scratch_dir("veil-pair-transport");
        let issued = 1_800_000_000u64;
        let out = create_identity(CreateIdentityOptions {
            veil_dir: dir.clone(),
            save_encrypted_with_password: None,
            argon2_params_override: None,
            extra_entropy: None,
            instance_label: "test-laptop".into(),
            pow_difficulty: crate::identity_policy::IdentityPolicy::DEFAULT_POW_DIFFICULTY,
            issued_at_unix: issued,
            valid_until_unix: issued + 7 * 86_400,
            algo: veil_types::SignatureAlgorithm::Ed25519,
        })
        .unwrap();
        let sov = SovereignIdentity::load_from_dir(&dir).unwrap();
        let id_seed = load_identity_sk(&dir).unwrap();
        let identity_sk = SigningKey::from_bytes(id_seed.as_array());
        let master_sk = SigningKey::from_bytes(&derive_master_sk_ed25519(&out.master_seed));
        Ctx {
            sov,
            master_sk,
            identity_sk,
        }
    }

    fn fresh_pair_secret() -> [u8; 32] {
        use rand_core::{OsRng, RngCore};
        let mut s = [0u8; 32];
        OsRng.fill_bytes(&mut s);
        s
    }

    fn spawn_ceremony(
        ctx: &Ctx,
        source_approves: bool,
        target_approves: bool,
    ) -> (
        Result<SourceTransportOutcome, PairTransportError>,
        Result<TargetTransportOutcome, PairTransportError>,
    ) {
        let pair_secret = fresh_pair_secret();
        let uri = PairingUri {
            node_id: *ctx.sov.node_id(),
            pair_secret,
            endpoint: "duplex://test".into(),
            expires_at_unix: 1_800_000_300,
        };
        let mut source = PairingSource::new(
            ctx.sov.document.clone(),
            ctx.identity_sk.clone(),
            ctx.master_sk.clone(),
            pair_secret,
            1_800_000_000,
        );
        let mut target = PairingTarget::new(uri, 1_800_000_000);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async move {
            let (mut src_end, mut tgt_end) = tokio::io::duplex(16 * 1024);
            let src_task =
                async { run_pair_source(&mut source, &mut src_end, |_oob| source_approves).await };
            let tgt_task =
                async { run_pair_target(&mut target, &mut tgt_end, |_oob| target_approves).await };
            tokio::join!(src_task, tgt_task)
        })
    }

    #[test]
    fn duplex_happy_path_both_approve() {
        let ctx = provision();
        let original_keys = ctx.sov.document.identity_keys.len();
        let (src, tgt) = spawn_ceremony(&ctx, true, true);
        let src = src.unwrap();
        let tgt = tgt.unwrap();

        // Both sides saw the same OOB.
        assert_eq!(src.oob_code, tgt.oob_code);
        assert_eq!(src.oob_code.len(), 7);

        // The finalized document has +1 IdentityKey.
        assert_eq!(
            src.finalized_document.identity_keys.len(),
            original_keys + 1,
        );
        assert_eq!(src.finalized_document.node_id, tgt.document.node_id);
        assert_eq!(src.appended_identity_key_idx as usize, original_keys,);
        assert_eq!(tgt.target_identity_key_idx as usize, original_keys);

        // Target's SK seed → pubkey matches the appended entry.
        let tgt_sk = SigningKey::from_bytes(&tgt.target_identity_sk_seed);
        let appended_pk =
            &src.finalized_document.identity_keys[src.appended_identity_key_idx as usize].pubkey;
        assert_eq!(appended_pk.as_slice(), tgt_sk.verifying_key().as_bytes());
    }

    #[test]
    fn duplex_target_aborts_surfaces_on_both_sides() {
        let ctx = provision();
        let (src, tgt) = spawn_ceremony(&ctx, true, false);
        assert!(
            matches!(src, Err(PairTransportError::TargetAborted)),
            "source should see TargetAborted, got {src:?}",
        );
        assert!(
            matches!(tgt, Err(PairTransportError::TargetAborted)),
            "target should self-report TargetAborted, got {tgt:?}",
        );
    }

    #[test]
    fn duplex_source_aborts_surfaces_as_source_aborted() {
        let ctx = provision();
        let (src, tgt) = spawn_ceremony(&ctx, false, true);
        assert!(
            matches!(src, Err(PairTransportError::SourceAborted)),
            "source should see SourceAborted, got {src:?}",
        );
        // Target finished fine crypto-wise — it doesn't know
        // source aborted. Its outcome is Ok (the document is
        // usable as the new local copy, though the CLI caller
        // shouldn't persist it if source isn't persisting).
        assert!(tgt.is_ok(), "target should return Ok, got {tgt:?}");
    }

    #[test]
    fn duplex_both_abort_surfaces_source_first() {
        // Both reject. Source's local decision fires before it
        // reads the Confirm frame, so SourceAborted takes
        // precedence over TargetAborted on the source side.
        let ctx = provision();
        let (src, tgt) = spawn_ceremony(&ctx, false, false);
        assert!(
            matches!(src, Err(PairTransportError::SourceAborted)),
            "got {src:?}",
        );
        assert!(
            matches!(tgt, Err(PairTransportError::TargetAborted)),
            "got {tgt:?}",
        );
    }

    // ── Framing unit tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn frame_round_trip_small() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let body = vec![0xAA; 128];
        let body_clone = body.clone();
        let writer = async move {
            write_frame(&mut a, &body_clone).await.unwrap();
        };
        let reader = async move { read_frame(&mut b).await.unwrap() };
        let (_, got) = tokio::join!(writer, reader);
        assert_eq!(got, body);
    }

    #[tokio::test]
    async fn frame_reader_rejects_oversized_declared_len() {
        let (mut a, mut b) = tokio::io::duplex(16);
        let bogus = (MAX_PAIR_FRAME_BODY as u32) + 1;
        let writer = async move {
            a.write_u32(bogus).await.unwrap();
            // Don't bother writing bytes — reader should reject
            // before trying to read_exact.
            drop(a);
        };
        let reader = async move { read_frame(&mut b).await };
        let (_, got) = tokio::join!(writer, reader);
        assert!(
            matches!(got, Err(PairTransportError::FrameOversized { got }) if got == bogus),
            "got {got:?}",
        );
    }

    #[tokio::test]
    async fn frame_reader_bubbles_eof_on_truncated_header() {
        let (a, mut b) = tokio::io::duplex(16);
        drop(a); // eof immediately
        let got = read_frame(&mut b).await;
        assert!(matches!(got, Err(PairTransportError::Io(_))), "got {got:?}");
    }

    /// Drive `run_pair_source_tcp` + `run_pair_target_tcp` against
    /// a real loopback port — same crypto flow as the duplex
    /// happy-path test but exercising the TCP accept/connect
    /// wrappers the CLI commands call.
    #[tokio::test]
    async fn tcp_wrappers_end_to_end_happy_path() {
        let ctx = provision();
        let pair_secret = fresh_pair_secret();
        let uri = PairingUri {
            node_id: *ctx.sov.node_id(),
            pair_secret,
            endpoint: "tcp://127.0.0.1:0".into(), // unused by test
            expires_at_unix: 1_800_000_300,
        };
        let mut source = PairingSource::new(
            ctx.sov.document.clone(),
            ctx.identity_sk.clone(),
            ctx.master_sk.clone(),
            pair_secret,
            1_800_000_000,
        );
        let mut target = PairingTarget::new(uri, 1_800_000_000);

        // Pick a free port on the loopback.
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let host_port = format!("127.0.0.1:{port}");

        let src = run_pair_source_tcp(&host_port, &mut source, |_| true);
        let tgt = async {
            // Small delay so source binds first. Not strictly
            // required (kernel often grants the port immediately)
            // but avoids a flake on slower hosts.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            run_pair_target_tcp(&host_port, &mut target, |_| true).await
        };
        let (src_out, tgt_out) = tokio::join!(src, tgt);
        let src = src_out.expect("source ok");
        let tgt = tgt_out.expect("target ok");
        assert_eq!(src.oob_code, tgt.oob_code);
    }
}
