// Demo app for veil_flutter — connects to a running veil daemon
// and shows live session count + mobile tier as the daemon pushes them.
//
// Run a daemon locally first:
//   veil-cli --config ~/.veil/node.toml node run --foreground
//
// then in this directory:
//   flutter run
//
// ─────────────────────────────────────────────────────────────────────
// Push wake-HMAC end-to-end — consumer FCM/APNs handler pattern
// (Epic 489.10).  The demo app itself does NOT bundle firebase_messaging
// (see push.dart rationale — keeps the plugin dep-light), so this is a
// reference comment block rather than live code.  A real consumer wires
// it like so:
//
// ```dart
// import 'package:firebase_messaging/firebase_messaging.dart';
// import 'dart:convert' show base64Decode;
// import 'package:veil_flutter/veil_flutter.dart';
//
// // `client` is the app's long-lived VeilClient (main isolate).  In a
// // pure FCM *background* isolate it is unreachable — there you'd open a
// // fresh client from the saved socket path (see VeilPush.drainMailbox).
// Future<void> _onPush(RemoteMessage message) async {
//   // 72-byte wake payload rides base64 under push data key "w":
//   //   FCM  → message.data["w"]
//   //   APNs → top-level "w"
//   final encoded = message.data['w'];
//   if (encoded == null) return; // not a wake-HMAC push — ignore.
//   final wakePayload = base64Decode(encoded);
//
//   // Key persisted at onboarding via VeilPush.storeWakeHmacKey
//   // (typically through generateAndRegisterWakeHmacKey).
//   final wakeHmacKey = await VeilPush.loadWakeHmacKey();
//   final receiverId = await client.nodeId(); // local node_id (32 B).
//
//   // requireAuth: true → fail CLOSED.  A missing key / forged / replayed
//   // / expired payload rejects BEFORE any foreground promotion or drain.
//   await VeilPush.handleWakeup(
//     wakePayload: wakePayload,
//     wakeHmacKey: wakeHmacKey,
//     receiverId: receiverId,
//     requireAuth: true,
//     onWake: () async {
//       // Drain the mailbox / force reconnect via the app's VeilClient.
//       await client.mailbox.fetch(
//         receiverId: receiverId,
//         authCookie: kRendezvousCookie,
//       );
//     },
//   );
// }
// ```
// ─────────────────────────────────────────────────────────────────────

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:veil_flutter/veil_flutter.dart';

void main() {
  runApp(const VeilDemoApp());
}

class VeilDemoApp extends StatelessWidget {
  const VeilDemoApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Veil demo',
      theme: ThemeData(useMaterial3: true, colorSchemeSeed: Colors.deepPurple),
      home: const _Home(),
    );
  }
}

class _Home extends StatefulWidget {
  const _Home();

  @override
  State<_Home> createState() => _HomeState();
}

class _HomeState extends State<_Home> {
  VeilClient? _client;
  String? _nodeId;
  int? _sessionCount;
  MobileBackgroundMode _tier = MobileBackgroundMode.foreground;
  String? _err;
  StreamSubscription<VeilEvent>? _eventSub;

  String _socketPath = '/run/veil/app.sock';

  @override
  void dispose() {
    _eventSub?.cancel();
    _client?.close();
    // Stop the foreground service so Android reclaims the process
    // when this widget tree is torn down (typically on logout).
    VeilBackground.stop();
    super.dispose();
  }

  Future<void> _connect() async {
    setState(() => _err = null);
    try {
      final c = await VeilClient.connect(_socketPath);
      final id = await c.nodeId();
      _eventSub = c.events().listen(_onEvent);
      // Epic 489.6: pin the process to foreground via a persistent
      // notification — without this, Android kills our daemon after
      // ~5-15 min in background.  No-op on iOS / desktop.
      await VeilBackground.start(
        title: 'Veil connected',
        text: 'Tap to open',
      );
      setState(() {
        _client = c;
        _nodeId = _hex(id);
      });
    } catch (e) {
      setState(() => _err = e.toString());
    }
  }

  void _onEvent(VeilEvent ev) {
    switch (ev.kind) {
      case VeilEventKind.sessionsChanged:
        setState(() => _sessionCount = ev.sessionCount);
      case VeilEventKind.mobileTierChanged:
        final t = ev.tierAfterChange;
        if (t != null) setState(() => _tier = t);
      case VeilEventKind.identityRotated:
        setState(() => _nodeId = _hex(ev.payload));
      case VeilEventKind.mailboxDrained:
        // Demo app does not actively await drain completion (would need
        // BG-handler integration).  Real BGProcessingTask consumers
        // subscribe through VeilPush.handleWakeup's onWake hook.
        break;
      case VeilEventKind.unknown:
        break;
    }
  }

  Future<void> _setTier(MobileBackgroundMode mode) async {
    final c = _client;
    if (c == null) return;
    try {
      await c.setBackgroundMode(mode);
      // Optimistic — the bus will also publish MOBILE_TIER_CHANGED; if it
      // races us the listener flips state identically.
      setState(() => _tier = mode);
    } catch (e) {
      setState(() => _err = e.toString());
    }
  }

  String _hex(List<int> bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Veil demo')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (_client == null) ...[
              const Text('Daemon socket path:'),
              TextFormField(
                initialValue: _socketPath,
                onChanged: (v) => _socketPath = v,
                decoration: const InputDecoration(border: OutlineInputBorder()),
              ),
              const SizedBox(height: 16),
              FilledButton(onPressed: _connect, child: const Text('Connect')),
            ] else ...[
              Text('node_id: ${_nodeId ?? "?"}', style: const TextStyle(fontFamily: 'monospace')),
              const SizedBox(height: 16),
              Text('sessions: ${_sessionCount ?? "(no event yet)"}'),
              const SizedBox(height: 16),
              const Text('Mobile background tier:'),
              Wrap(spacing: 8, children: [
                for (final m in MobileBackgroundMode.values)
                  ChoiceChip(
                    label: Text(m.name),
                    selected: _tier == m,
                    onSelected: (_) => _setTier(m),
                  ),
              ]),
            ],
            if (_err != null) ...[
              const SizedBox(height: 16),
              Text(_err!, style: const TextStyle(color: Colors.red)),
            ],
          ],
        ),
      ),
    );
  }
}
