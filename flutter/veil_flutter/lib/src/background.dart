// Foreground-service control from Dart side (Epic 489.6).
//
// Problem: Android aggressively kills backgrounded processes after
// ~5-15 minutes.  Without a foreground service, the veil daemon
// embedded in the Flutter process stops receiving messages whenever
// the user backgrounds the app.
//
// Solution: a Kotlin foreground service ([`VeilDaemonService`])
// that displays a persistent notification.  Android treats services
// with visible notifications as "doing user-visible work" and leaves
// them alone.
//
// Lifecycle integration pattern for consumer apps:
//
// ```dart
// class _MyAppState extends State<MyApp> with WidgetsBindingObserver {
//   @override
//   void initState() {
//     super.initState();
//     WidgetsBinding.instance.addObserver(this);
//     VeilBackground.start(title: 'MyApp connected', text: 'Online via veil');
//   }
//
//   @override
//   void dispose() {
//     WidgetsBinding.instance.removeObserver(this);
//     VeilBackground.stop();  // user logged out / app exit
//     super.dispose();
//   }
//
//   @override
//   void didChangeAppLifecycleState(AppLifecycleState state) {
//     // When app goes to background, the foreground service keeps the
//     // process alive.  When user explicitly stops the daemon (logout),
//     // call VeilBackground.stop() so Android can reclaim the process.
//   }
// }
// ```
//
// Platform support: Android only.  iOS doesn't have an equivalent
// "stay alive forever" mechanism — it uses BGProcessingTask + push
// notifications instead (Epic 489.10).  Calling `start` on iOS / linux
// / macos / windows is a silent no-op so cross-platform code doesn't
// need a platform check.

import 'dart:io' show Platform;

import 'package:flutter/services.dart' show MethodChannel;

const MethodChannel _channel = MethodChannel('veil_flutter/lifecycle');

/// Android foreground-service controls.
///
/// All methods are silent no-ops on platforms that don't have an
/// equivalent mechanism (iOS, Linux, macOS, Windows).  The class
/// itself (rather than top-level functions) groups them so consumers
/// can `VeilBackground.start(...)` rather than worrying about
/// import collisions.
class VeilBackground {
  VeilBackground._();  // not instantiable

  /// Start the foreground service.  Returns immediately; the service
  /// itself takes over keeping the process alive.
  ///
  /// [title] and [text] populate the persistent notification visible
  /// in the status bar.  When omitted, the plugin uses defaults
  /// suitable for a connection-maintaining service ("Veil running").
  ///
  /// Idempotent — calling start when the service is already running
  /// just refreshes the notification text.
  static Future<void> start({String? title, String? text}) async {
    if (!Platform.isAndroid) return;
    await _channel.invokeMethod<void>('startBackgroundService', <String, dynamic>{
      if (title != null) 'title': title,
      if (text  != null) 'text':  text,
    });
  }

  /// Stop the foreground service.  Use this on explicit user
  /// "log out" / "go offline" actions.  After stop, Android may
  /// reclaim the process under memory pressure.
  ///
  /// No-op when the service isn't running OR the platform isn't Android.
  static Future<void> stop() async {
    if (!Platform.isAndroid) return;
    await _channel.invokeMethod<void>('stopBackgroundService');
  }
}
