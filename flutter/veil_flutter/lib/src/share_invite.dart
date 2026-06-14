// Bootstrap-invite share UI (Epic 489.7 generator side).
//
// Companion to `VeilPairingDialog` (consume side): existing user
// opens this dialog to render their own daemon's bootstrap-invite URI
// as a QR code (primary path) plus the raw URI string as fallback
// for paste-into-messaging-channel.  Optional passphrase encrypts the
// envelope (`veil:pair?…`) for sharing on public channels.
//
// Usage:
//
// ```dart
// await showDialog<void>(
//   context: context,
//   builder: (ctx) => VeilShareInviteDialog(client: veilClient),
// );
// ```

import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show Clipboard, ClipboardData;
import 'package:qr_flutter/qr_flutter.dart';

import 'client.dart';
import 'types.dart';

/// Material-3 dialog that fetches a bootstrap-invite URI from the
/// connected [VeilClient] and displays it as a QR code + copy-button.
/// Optional passphrase toggle encrypts the envelope.
class VeilShareInviteDialog extends StatefulWidget {
  const VeilShareInviteDialog({
    required this.client,
    this.title = 'Share my invite',
    super.key,
  });

  /// Bound veil client — used to invoke [VeilClient.createBootstrapInvite].
  final VeilClient client;

  /// Dialog header text.
  final String title;

  @override
  State<VeilShareInviteDialog> createState() => _VeilShareInviteDialogState();
}

class _VeilShareInviteDialogState extends State<VeilShareInviteDialog> {
  final _passwordController = TextEditingController();
  bool _useEncryption = false;
  bool _busy = false;
  CreateBootstrapInviteResult? _result;
  String? _error;

  @override
  void initState() {
    super.initState();
    // Auto-fetch the plain (unencrypted) invite on open.  User toggles
    // encryption + retries if they want to share over a public channel.
    WidgetsBinding.instance.addPostFrameCallback((_) => _fetch());
  }

  @override
  void dispose() {
    _passwordController.dispose();
    super.dispose();
  }

  Future<void> _fetch() async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final result = await widget.client.createBootstrapInvite(
        password: _useEncryption && _passwordController.text.isNotEmpty
            ? _passwordController.text
            : null,
      );
      if (!mounted) return;
      setState(() => _result = result);
    } catch (e) {
      if (!mounted) return;
      setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _copyUri() async {
    final uri = _result?.uri;
    if (uri == null || uri.isEmpty) return;
    await Clipboard.setData(ClipboardData(text: uri));
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Invite URI copied to clipboard'),
        duration: Duration(seconds: 2),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Dialog(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 480, maxHeight: 720),
        child: Padding(
          padding: const EdgeInsets.fromLTRB(16, 16, 16, 16),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Row(
                children: [
                  Expanded(
                    child: Text(
                      widget.title,
                      style: Theme.of(context).textTheme.titleLarge,
                    ),
                  ),
                  IconButton(
                    icon: const Icon(Icons.close),
                    tooltip: 'Close',
                    onPressed: () => Navigator.of(context).pop(),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              _buildBody(),
              const SizedBox(height: 12),
              _buildEncryptionToggle(),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildBody() {
    if (_busy) {
      return const Padding(
        padding: EdgeInsets.symmetric(vertical: 48),
        child: Center(child: CircularProgressIndicator()),
      );
    }
    if (_error != null) {
      return _buildErrorBox('Could not reach daemon', _error!);
    }
    final result = _result;
    if (result == null) {
      return const Padding(
        padding: EdgeInsets.symmetric(vertical: 48),
        child: Center(child: Text('Waiting…')),
      );
    }
    switch (result.status) {
      case CreateBootstrapInviteStatus.ok:
        return _buildOkBox(result.uri);
      case CreateBootstrapInviteStatus.notConfigured:
        return _buildErrorBox(
          'Identity not configured',
          result.detail ??
              'Daemon has no [identity] or no [[listen]] entry.  Run '
                  '`veil-cli identity standalone` + add a listen address.',
        );
      case CreateBootstrapInviteStatus.badPassword:
        return _buildErrorBox(
          'Bad passphrase',
          result.detail ?? 'Passphrase empty or whitespace-only',
        );
      case CreateBootstrapInviteStatus.internalError:
      case CreateBootstrapInviteStatus.unknown:
        return _buildErrorBox(
          'Daemon error',
          result.detail ?? 'Unknown daemon error encoding the invite',
        );
    }
  }

  Widget _buildOkBox(String uri) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Center(
          child: Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Colors.white,
              borderRadius: BorderRadius.circular(8),
              border: Border.all(
                color: Theme.of(context).colorScheme.outline,
              ),
            ),
            child: QrImageView(
              data: uri,
              version: QrVersions.auto,
              size: 280,
              gapless: false,
              errorCorrectionLevel: QrErrorCorrectLevel.M,
            ),
          ),
        ),
        const SizedBox(height: 12),
        Text(
          'Or share the raw URI:',
          style: Theme.of(context).textTheme.bodySmall,
        ),
        const SizedBox(height: 4),
        SelectableText(
          uri,
          style: Theme.of(context).textTheme.bodySmall?.copyWith(
                fontFamily: 'monospace',
              ),
          maxLines: 4,
        ),
        const SizedBox(height: 8),
        Row(
          mainAxisAlignment: MainAxisAlignment.end,
          children: [
            FilledButton.icon(
              icon: const Icon(Icons.copy),
              label: const Text('Copy URI'),
              onPressed: _copyUri,
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildErrorBox(String title, String detail) {
    final cs = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: cs.errorContainer.withValues(alpha: 0.3),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Icons.error_outline, color: cs.error),
              const SizedBox(width: 8),
              Text(title,
                  style: Theme.of(context).textTheme.titleMedium?.copyWith(
                        color: cs.error,
                      )),
            ],
          ),
          const SizedBox(height: 8),
          Text(detail, style: Theme.of(context).textTheme.bodySmall),
          const SizedBox(height: 12),
          TextButton(
            onPressed: _fetch,
            child: const Text('Retry'),
          ),
        ],
      ),
    );
  }

  Widget _buildEncryptionToggle() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        SwitchListTile(
          contentPadding: EdgeInsets.zero,
          title: const Text('Encrypt with passphrase'),
          subtitle: const Text(
            'Required when sharing over a public channel (Telegram, email…).  '
            'Receiver must supply the same passphrase.',
          ),
          value: _useEncryption,
          onChanged: _busy
              ? null
              : (v) {
                  setState(() {
                    _useEncryption = v;
                    if (!v) _passwordController.clear();
                  });
                  if (!v) _fetch();
                },
        ),
        if (_useEncryption) ...[
          TextField(
            controller: _passwordController,
            obscureText: true,
            decoration: const InputDecoration(
              border: OutlineInputBorder(),
              labelText: 'Passphrase',
              hintText: '12+ characters, mix of types',
            ),
            onSubmitted: (_) => _fetch(),
          ),
          const SizedBox(height: 8),
          Align(
            alignment: Alignment.centerRight,
            child: FilledButton.icon(
              icon: const Icon(Icons.lock),
              label: const Text('Regenerate with passphrase'),
              onPressed: _busy ||
                      _passwordController.text.trim().isEmpty
                  ? null
                  : _fetch,
            ),
          ),
        ],
      ],
    );
  }
}
