// Pairing UX (Epic 489.7) — QR-scan + manual-paste invite consumption.
//
// Three entry points for the new-user (consume) side:
//   1. QR scan via `mobile_scanner` package — primary path, fastest UX.
//   2. Manual paste field — fallback when camera unavailable / scan fails.
//   3. HTTPS bootstrap URL field — for `https://invite.example.com/...`
//      links shared via messaging apps.
//
// All three converge to [VeilClient.joinBootstrapUri], so the
// passphrase-prompt / signed-verify logic lives in one place.
//
// Generator side (existing user shares their own invite as a QR) lives
// in the companion file [`share_invite.dart`](share_invite.dart) —
// `VeilShareInviteDialog`.  Both files cover the QR-code-pairing
// flow end-to-end.
//
// Usage:
//
// ```dart
// final result = await showDialog<JoinBootstrapResult>(
//   context: context,
//   builder: (ctx) => VeilPairingDialog(client: veilClient),
// );
// if (result?.status == JoinBootstrapStatus.ok) { /* paired */ }
// ```

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import 'client.dart';
import 'types.dart';

/// Material-3 pairing dialog.  Shows tabs for three pairing methods +
/// inline passphrase prompt + actionable error states.
///
/// Returns the final [JoinBootstrapResult] on pop (or `null` if the
/// user dismissed without completing).
class VeilPairingDialog extends StatefulWidget {
  const VeilPairingDialog({
    required this.client,
    this.title = 'Pair with a peer',
    this.expectedIssuerPk,
    super.key,
  });

  /// Bound veil client — used to invoke [VeilClient.joinBootstrapUri].
  final VeilClient client;

  /// Dialog header text.
  final String title;

  /// For signed invites only: base64-encoded issuer Ed25519 pubkey.
  /// Required for `veil:signed-invite?…` URIs; leave null for
  /// plain / encrypted invites.
  final String? expectedIssuerPk;

  @override
  State<VeilPairingDialog> createState() => _VeilPairingDialogState();
}

class _VeilPairingDialogState extends State<VeilPairingDialog>
    with SingleTickerProviderStateMixin {
  late final TabController _tabController;
  final _pasteController = TextEditingController();
  final _httpsController = TextEditingController();
  final _passwordController = TextEditingController();

  bool _busy = false;
  String? _scanError;
  String? _lastUriTried;
  JoinBootstrapStatus? _lastStatus;
  String? _lastDetail;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 3, vsync: this);
  }

  @override
  void dispose() {
    _tabController.dispose();
    _pasteController.dispose();
    _httpsController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  // ── Pairing core ─────────────────────────────────────────────────

  /// Single entry-point all three flows funnel through.  Calls
  /// [VeilClient.joinBootstrapUri], handles passphrase-required
  /// status by re-prompting and retrying, and updates local state with the
  /// result.  Returns `true` if the result is a terminal "good" outcome
  /// ([JoinBootstrapStatus.ok] or [alreadyRegistered]) — the dialog
  /// pops on `true`.
  Future<bool> _attemptJoin(
    String uri, {
    String? overridePassword,
  }) async {
    if (_busy) return false;
    setState(() {
      _busy = true;
      _lastUriTried = uri;
      _lastStatus = null;
      _lastDetail = null;
    });
    // Precedence-explicit: prefer the explicit override, else fall
    // back to the inline-prompt field (if operator already entered
    // passphrase), else NULL.
    final pw = overridePassword ??
        (_passwordController.text.isEmpty
            ? null
            : _passwordController.text);
    try {
      final res = await widget.client.joinBootstrapUri(
        uri: uri,
        password: pw,
        expectedIssuerPk: widget.expectedIssuerPk,
      );
      if (!mounted) return false;
      setState(() {
        _lastStatus = res.status;
        _lastDetail = res.detail;
      });
      switch (res.status) {
        case JoinBootstrapStatus.ok:
        case JoinBootstrapStatus.alreadyRegistered:
          Navigator.of(context).pop(res);
          return true;
        case JoinBootstrapStatus.passwordRequired:
        case JoinBootstrapStatus.passwordWrong:
          // Surface a passphrase prompt inline; user retries.
          return false;
        default:
          // Terminal error — keep dialog open, show status banner.
          return false;
      }
    } catch (e) {
      if (!mounted) return false;
      setState(() {
        _lastDetail = e.toString();
        _lastStatus = JoinBootstrapStatus.internalError;
      });
      return false;
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  // ── Builders ─────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    return Dialog(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 480, maxHeight: 640),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(24, 20, 16, 8),
              child: Row(
                children: [
                  Expanded(
                    child: Text(
                      widget.title,
                      style: Theme.of(context).textTheme.titleLarge,
                    ),
                  ),
                  IconButton(
                    icon: const Icon(Icons.close),
                    tooltip: 'Cancel',
                    onPressed: () => Navigator.of(context).pop(),
                  ),
                ],
              ),
            ),
            TabBar(
              controller: _tabController,
              tabs: const [
                Tab(icon: Icon(Icons.qr_code_scanner), text: 'Scan QR'),
                Tab(icon: Icon(Icons.content_paste), text: 'Paste URI'),
                Tab(icon: Icon(Icons.link), text: 'HTTPS link'),
              ],
            ),
            Expanded(
              child: TabBarView(
                controller: _tabController,
                children: [
                  _buildQrTab(),
                  _buildPasteTab(),
                  _buildHttpsTab(),
                ],
              ),
            ),
            if (_lastStatus != null) _buildStatusBanner(),
            if (_needsPassword()) _buildPasswordPrompt(),
          ],
        ),
      ),
    );
  }

  bool _needsPassword() =>
      _lastStatus == JoinBootstrapStatus.passwordRequired ||
      _lastStatus == JoinBootstrapStatus.passwordWrong;

  Widget _buildQrTab() {
    if (_scanError != null) {
      return Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.warning_amber, size: 48),
            const SizedBox(height: 12),
            Text('Camera unavailable',
                style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            Text(_scanError!, textAlign: TextAlign.center),
            const SizedBox(height: 16),
            TextButton(
              onPressed: () => _tabController.animateTo(1),
              child: const Text('Use paste instead'),
            ),
          ],
        ),
      );
    }
    return ClipRRect(
      borderRadius: BorderRadius.circular(8),
      child: MobileScanner(
        onDetect: _onBarcodeDetect,
        tapToFocus: true,
        errorBuilder: (context, error) {
          // Cache the error To surface a fallback hint; the widget will
          // rebuild with the error variant of this tab.
          WidgetsBinding.instance.addPostFrameCallback((_) {
            if (!mounted) return;
            setState(() {
              _scanError = error.errorDetails?.message ?? 'unknown';
            });
          });
          return const Center(child: CircularProgressIndicator());
        },
      ),
    );
  }

  void _onBarcodeDetect(BarcodeCapture capture) {
    if (_busy) return;
    for (final code in capture.barcodes) {
      final raw = code.rawValue;
      if (raw == null || raw.isEmpty) continue;
      // Pause scanner and attempt the join.  If the join needs a
      // passphrase, the dialog UI surfaces the prompt inline.
      _attemptJoin(raw);
      return;
    }
  }

  Widget _buildPasteTab() {
    return Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(
            'Paste an `veil:` invite URI',
            style: Theme.of(context).textTheme.bodyMedium,
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _pasteController,
            maxLines: 4,
            decoration: const InputDecoration(
              border: OutlineInputBorder(),
              hintText: 'veil:invite?…',
            ),
          ),
          const SizedBox(height: 12),
          FilledButton.icon(
            icon: const Icon(Icons.check),
            label: const Text('Pair'),
            onPressed: _busy
                ? null
                : () {
                    final uri = _pasteController.text.trim();
                    if (uri.isNotEmpty) _attemptJoin(uri);
                  },
          ),
        ],
      ),
    );
  }

  Widget _buildHttpsTab() {
    return Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(
            'Paste an HTTPS bootstrap link',
            style: Theme.of(context).textTheme.bodyMedium,
          ),
          const SizedBox(height: 4),
          Text(
            'Used when sharing invites through regular messaging apps. '
            'Daemon fetches the invite bundle over HTTPS.',
            style: Theme.of(context).textTheme.bodySmall,
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _httpsController,
            keyboardType: TextInputType.url,
            decoration: const InputDecoration(
              border: OutlineInputBorder(),
              hintText: 'https://invite.example.com/abc123',
            ),
          ),
          const SizedBox(height: 12),
          FilledButton.icon(
            icon: const Icon(Icons.cloud_download),
            label: const Text('Pair'),
            onPressed: _busy
                ? null
                : () {
                    final url = _httpsController.text.trim();
                    if (url.isNotEmpty) _attemptJoin(url);
                  },
          ),
        ],
      ),
    );
  }

  Widget _buildStatusBanner() {
    final status = _lastStatus!;
    final (icon, color, message) = _statusPresentation(status);
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      color: color.withValues(alpha: 0.1),
      child: Row(
        children: [
          Icon(icon, color: color),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(message, style: TextStyle(color: color)),
                if (_lastDetail != null && _lastDetail!.isNotEmpty)
                  Text(
                    _lastDetail!,
                    style: Theme.of(context)
                        .textTheme
                        .bodySmall
                        ?.copyWith(color: color.withValues(alpha: 0.85)),
                  ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  (IconData, Color, String) _statusPresentation(JoinBootstrapStatus s) {
    final cs = Theme.of(context).colorScheme;
    switch (s) {
      case JoinBootstrapStatus.ok:
      case JoinBootstrapStatus.alreadyRegistered:
        return (Icons.check_circle, cs.primary, 'Paired successfully');
      case JoinBootstrapStatus.invalidUri:
        return (
          Icons.broken_image,
          cs.error,
          'Invite URI could not be decoded — check version compatibility',
        );
      case JoinBootstrapStatus.passwordRequired:
        return (
          Icons.password,
          cs.primary,
          'This invite is encrypted — enter the passphrase below',
        );
      case JoinBootstrapStatus.passwordWrong:
        return (
          Icons.password,
          cs.error,
          'Wrong passphrase — check case / spaces and try again',
        );
      case JoinBootstrapStatus.signatureInvalid:
        return (
          Icons.gpp_bad,
          cs.error,
          'Signature did not verify — invite is tampered or from a '
              'different issuer',
        );
      case JoinBootstrapStatus.internalError:
      case JoinBootstrapStatus.unknown:
        return (
          Icons.error,
          cs.error,
          'Daemon could not process this invite — check connection and retry',
        );
    }
  }

  Widget _buildPasswordPrompt() {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
      child: Row(
        children: [
          Expanded(
            child: TextField(
              controller: _passwordController,
              obscureText: true,
              autofocus: true,
              decoration: const InputDecoration(
                border: OutlineInputBorder(),
                labelText: 'Passphrase',
              ),
              onSubmitted: (_) => _retryWithPassword(),
            ),
          ),
          const SizedBox(width: 8),
          FilledButton(
            onPressed: _busy ? null : _retryWithPassword,
            child: const Text('Retry'),
          ),
        ],
      ),
    );
  }

  void _retryWithPassword() {
    final uri = _lastUriTried;
    if (uri == null) return;
    _attemptJoin(uri, overridePassword: _passwordController.text);
  }
}
