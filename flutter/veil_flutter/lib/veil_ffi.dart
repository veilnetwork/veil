/// Flutter-engine-free Dart FFI surface for command-line and server hosts.
///
/// Unlike `veil_flutter.dart`, this entrypoint exports no widgets, lifecycle
/// bindings, platform channels, QR or camera code. A standalone Dart AOT
/// executable can therefore use the same native client without linking the
/// Flutter engine.
library;

export 'src/client.dart'
    show VeilClient, AppHandle, veilSealBytes, veilUnsealBytes;
export 'src/crypto.dart' show VeilCrypto;
export 'src/identity.dart'
    show
        generateMasterPhrase,
        hasBip39WordCount,
        restoreIdentity,
        restoreIdentityEncrypted,
        validateBip39Phrase;
export 'src/mailbox.dart' show MailboxOpened, VeilMailbox;
export 'src/nickname.dart'
    show
        NicknameMineOutcome,
        ResolvedNickname,
        claimNickname,
        claimNicknameAsync,
        mineNicknameChunk,
        mineNicknameChunkAsync,
        nicknameLengthFloor,
        normalizeNickname,
        resolveNickname,
        resolveNicknameAsync;
export 'src/sovereign_signer.dart'
    show
        VeilSovereignSigner,
        createHybrid512SovereignBundle,
        exportSovereignRecoveryCertificate,
        generateSovereignRecoveryCode,
        verifySovereignSignature;
export 'src/stream.dart' show VeilStream, VeilAnonStream;
export 'src/types.dart'
    show
        CreateBootstrapInviteResult,
        CreateBootstrapInviteStatus,
        IncomingMessage,
        JoinBootstrapResult,
        JoinBootstrapStatus,
        MailboxBlob,
        MailboxPutResult,
        MailboxPutStatus,
        MobileBackgroundMode,
        NetworkKind,
        VeilEvent,
        VeilEventKind,
        VeilException,
        VeilPeer,
        VeilPeerState,
        VeilPeerDirection,
        RendezvousReplica,
        WakePayloadVerdict;
