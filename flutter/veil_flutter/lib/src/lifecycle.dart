// App-lifecycle + network-state glue (Epic 489.3 / 489.4 / 489.5).
//
// Plumbs:
//   * `WidgetsBindingObserver` → `VeilClient.setBackgroundMode` so
//     the daemon scales keepalive cadence + suppresses background
//     maintenance when the host moves к lowPower.
//   * `connectivity_plus` stream → `VeilClient.notifyNetworkChanged`
//     so the daemon eager-rebuilds sessions on а Wi-Fi → Cellular flip
//     (instead of waiting for а keepalive timeout to notice dead sockets).
//
// Usage:
//
// ```dart
// final client = await VeilClient.connect(socket);
// final lifecycle = VeilLifecycleBinding(client)
//   ..attachConnectivity()       // optional — uses connectivity_plus
//   ..attachAppLifecycle();      // optional — uses WidgetsBinding
//
// // ... app runs ...
//
// await lifecycle.dispose();     // detaches observers (idempotent)
// await client.close();
// ```
//
// Each `attach*` method is opt-in so apps that already manage their own
// lifecycle (e.g. background isolates) can disable individual streams.

import 'dart:async';

import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:flutter/widgets.dart';

import 'client.dart';
import 'types.dart';

/// Lifecycle + network-state observer that translates platform events
/// into FFI calls on а bound [VeilClient].
///
/// Safe к use even if some `attach*` calls are skipped — each method
/// is independent.  All registrations are reversible через [dispose].
class VeilLifecycleBinding with WidgetsBindingObserver {
  VeilLifecycleBinding(this._client);

  final VeilClient _client;

  bool _appLifecycleAttached = false;
  bool _disposed = false;

  StreamSubscription<List<ConnectivityResult>>? _connectivitySub;

  /// Last tier we pushed к the daemon — debounces redundant calls when
  /// Flutter delivers identical `didChangeAppLifecycleState` events
  /// (happens on iOS during transitions).
  MobileBackgroundMode? _lastPushedTier;

  /// Last network kind we pushed к the daemon — same debouncing
  /// rationale; connectivity_plus emits duplicate events во время
  /// rapid switches.
  NetworkKind? _lastPushedNet;

  /// Register as а [WidgetsBindingObserver] so app-lifecycle changes
  /// drive `setBackgroundMode`.  Mapping:
  ///   * [AppLifecycleState.resumed] → [MobileBackgroundMode.foreground]
  ///   * [AppLifecycleState.inactive] → [MobileBackgroundMode.active]
  ///   * [AppLifecycleState.paused] → [MobileBackgroundMode.lowPower]
  ///   * [AppLifecycleState.hidden] → [MobileBackgroundMode.lowPower]
  ///   * [AppLifecycleState.detached] → no-op (caller should [close])
  ///
  /// Pushes the current tier immediately so the daemon sees the
  /// starting state before any user gesture changes it.
  void attachAppLifecycle() {
    _ensureNotDisposed();
    if (_appLifecycleAttached) return;
    WidgetsBinding.instance.addObserver(this);
    _appLifecycleAttached = true;
    // Push current state synchronously.  On cold start that's typically
    // `resumed`, но this also handles "binding created mid-paused"
    // (background-isolate-spawned-while-app-in-background) cases.
    final initial = WidgetsBinding.instance.lifecycleState;
    if (initial != null) {
      final tier = _lifecycleStateToTier(initial);
      if (tier != null) _maybePushTier(tier);
    }
  }

  /// Subscribe к `connectivity_plus` и translate each emitted
  /// connectivity-result list к а [NetworkKind] sent to the daemon
  /// via [VeilClient.notifyNetworkChanged].
  ///
  /// Mapping favours the "richest" simultaneous attachment:
  ///   * wifi → [NetworkKind.wifi]
  ///   * ethernet → [NetworkKind.ethernet]
  ///   * mobile → [NetworkKind.cellular]
  ///   * none → [NetworkKind.offline]
  ///   * vpn / bluetooth / other → [NetworkKind.unknown]
  ///
  /// Wi-Fi + cellular simultaneously (rare, e.g. tethering) → wifi
  /// wins (cheapest plan для the daemon's rate-control heuristics).
  ///
  /// Pushes the current connectivity immediately by querying
  /// `Connectivity.checkConnectivity()`.
  Future<void> attachConnectivity() async {
    _ensureNotDisposed();
    if (_connectivitySub != null) return;
    final conn = Connectivity();
    // Push current state before subscribing — keeps daemon in sync
    // на cold start where no event has fired yet.
    try {
      final current = await conn.checkConnectivity();
      _maybePushNet(_resultsToNetworkKind(current));
    } catch (_) {
      // Platform-side init can fail on rare Android OEMs (locked-down
      // perms).  Swallow — the stream subscription below will catch up
      // как soon as the OS delivers а real event.
    }
    if (_disposed) return; // raced а dispose() while awaiting init
    _connectivitySub = conn.onConnectivityChanged.listen(
      (results) => _maybePushNet(_resultsToNetworkKind(results)),
      onError: (_) {
        // Don't propagate — connectivity errors should not kill the app.
      },
    );
  }

  /// Detach observers + cancel subscriptions.  Idempotent.  Does NOT
  /// close the underlying [VeilClient] — caller manages that.
  Future<void> dispose() async {
    if (_disposed) return;
    _disposed = true;
    if (_appLifecycleAttached) {
      WidgetsBinding.instance.removeObserver(this);
      _appLifecycleAttached = false;
    }
    final sub = _connectivitySub;
    _connectivitySub = null;
    if (sub != null) {
      await sub.cancel();
    }
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (_disposed) return;
    final tier = _lifecycleStateToTier(state);
    if (tier != null) _maybePushTier(tier);
  }

  // ── Internal helpers ──────────────────────────────────────────────

  /// Map Flutter lifecycle states к the daemon's tier byte.
  /// Returns null для states we don't translate ([detached] — app
  /// is being torn down, no point notifying).
  static MobileBackgroundMode? _lifecycleStateToTier(AppLifecycleState s) {
    switch (s) {
      case AppLifecycleState.resumed:
        return MobileBackgroundMode.foreground;
      case AppLifecycleState.inactive:
        return MobileBackgroundMode.active;
      case AppLifecycleState.paused:
      case AppLifecycleState.hidden:
        return MobileBackgroundMode.lowPower;
      case AppLifecycleState.detached:
        return null;
    }
  }

  /// Map а list of ConnectivityResult (newer connectivity_plus API
  /// returns multiple simultaneously-active types) к а single
  /// [NetworkKind] using the priority hierarchy documented above.
  static NetworkKind _resultsToNetworkKind(List<ConnectivityResult> rs) {
    if (rs.isEmpty || rs.every((r) => r == ConnectivityResult.none)) {
      return NetworkKind.offline;
    }
    if (rs.contains(ConnectivityResult.wifi)) return NetworkKind.wifi;
    if (rs.contains(ConnectivityResult.ethernet)) return NetworkKind.ethernet;
    if (rs.contains(ConnectivityResult.mobile)) return NetworkKind.cellular;
    // vpn / bluetooth / other — daemon doesn't have а specific tier,
    // surface as unknown so it falls к its default keepalive/probe path.
    return NetworkKind.unknown;
  }

  void _maybePushTier(MobileBackgroundMode tier) {
    if (_lastPushedTier == tier) return;
    _lastPushedTier = tier;
    // Fire-and-forget; setBackgroundMode is а one-shot daemon call.
    _client.setBackgroundMode(tier).catchError((_) {
      // Daemon might be closed by now — already-closed exception is
      // fine, anything else is logged по the FFI layer.  No-op here.
    });
  }

  void _maybePushNet(NetworkKind kind) {
    if (_lastPushedNet == kind) return;
    _lastPushedNet = kind;
    _client.notifyNetworkChanged(kind).catchError((_) {
      // Same rationale as _maybePushTier.
    });
  }

  void _ensureNotDisposed() {
    if (_disposed) {
      throw StateError('VeilLifecycleBinding is disposed');
    }
  }
}
