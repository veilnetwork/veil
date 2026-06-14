/// Dart-FFI bindings for the veil daemon (Epic 489.3).
///
/// Usage:
/// ```dart
/// final client = await VeilClient.connect('/run/veil/app.sock');
/// final identity = await client.nodeId();
///
/// // Subscribe to push events for battery-friendly UI updates.
/// client.events().listen((ev) {
///   if (ev.kind == VeilEventKind.sessionsChanged) {
///     print('Sessions changed: ${ev.sessionCount}');
///   }
/// });
///
/// // Bind an endpoint and exchange messages with peers.
/// final app = await client.bind(namespace: 'demo', name: 'echo');
/// app.messages().listen((msg) => print('Got ${msg.data.length} B'));
/// await app.send(
///   dstNodeId: peerNodeId,
///   dstAppId:  peerAppId,
///   dstEndpointId: 0,
///   data: Uint8List.fromList([1, 2, 3]),
/// );
/// ```
library veil_flutter;

export 'src/background.dart' show VeilBackground;
export 'src/client.dart' show VeilClient, AppHandle;
export 'src/identity.dart'
    show
        hasBip39WordCount,
        restoreIdentity,
        restoreIdentityEncrypted,
        validateBip39Phrase;
export 'src/lifecycle.dart' show VeilLifecycleBinding;
export 'src/mailbox.dart' show VeilMailbox;
export 'src/multi_device_pairing.dart'
    show VeilMultiDevicePairingDialog, PairingRole;
export 'src/pairing.dart' show VeilPairingDialog;
export 'src/push.dart' show VeilPush, PushProvider;
export 'src/share_invite.dart' show VeilShareInviteDialog;
export 'src/stream.dart' show VeilStream;
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
        PairCreateInviteResult,
        PairFrameResult,
        PairOobResult,
        PairSourceStatus,
        PairStatusResult,
        PairTargetStatus,
        RendezvousReplica,
        WakePayloadVerdict;
