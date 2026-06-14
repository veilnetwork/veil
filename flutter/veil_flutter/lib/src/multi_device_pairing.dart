// Multi-device pairing dialog (Epic 489.8).
//
// Workflow:
// - Source (existing device c master_seed):
//     1. Enter master passphrase → daemon generates pairing URI.
//     2. Show URI as QR + text → user sends to target.
//     3. Paste target's Hello bytes → daemon emits Cert + OOB code.
//     4. Show Cert bytes for transport to target; show OOB to compare.
//     5. Paste target's Confirm bytes → daemon finalizes.
//
// - Target (new device):
//     1. Paste / scan source URI.
//     2. Daemon emits Hello bytes → user sends to source.
//     3. Paste source's Cert bytes → daemon shows OOB.
//     4. Compare OOB with source's screen → press "match"/"no match".
//     5. Daemon emits Confirm bytes; on match also persists new identity.
//
// Transport (Hello / Cert / Confirm bytes) is hex-encoded pasteable
// strings in this MVP.  QR-scanner for transport bytes can be added
// in a follow-up — the byte sizes (≤ 16 KiB usually) are beyond
// typical QR capacity (Version 40 fits ~2.9 KiB binary), so paste
// is the realistic transport.

import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show Clipboard, ClipboardData;
import 'package:qr_flutter/qr_flutter.dart';

import 'client.dart';
import 'types.dart';

/// Pairing role chosen at dialog open.
enum PairingRole { source, target }

/// Material-3 multi-screen dialog driving either side of a pairing
/// ceremony.  Stateful — keeps step-by-step transport bytes between
/// daemon round-trips.  Returns `true` on success, `false` on user
/// cancel, throws on transport error.
class VeilMultiDevicePairingDialog extends StatefulWidget {
  const VeilMultiDevicePairingDialog({
    required this.client,
    required this.role,
    super.key,
  });

  final VeilClient client;
  final PairingRole role;

  @override
  State<VeilMultiDevicePairingDialog> createState() =>
      _VeilMultiDevicePairingDialogState();
}

class _VeilMultiDevicePairingDialogState
    extends State<VeilMultiDevicePairingDialog> {
  int _step = 0;
  bool _busy = false;
  String? _error;

  // Source-side state
  final _masterPasswordCtl = TextEditingController();
  String? _pairingUri;
  final _helloBytesCtl = TextEditingController();
  Uint8List? _certBytes;
  String? _sourceOob;
  final _confirmBytesCtl = TextEditingController();

  // Target-side state
  final _uriPasteCtl = TextEditingController();
  Uint8List? _helloBytes;
  final _certBytesCtl = TextEditingController();
  String? _targetOob;
  Uint8List? _confirmBytesOut;

  @override
  void dispose() {
    _masterPasswordCtl.dispose();
    _helloBytesCtl.dispose();
    _confirmBytesCtl.dispose();
    _uriPasteCtl.dispose();
    _certBytesCtl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final title = widget.role == PairingRole.source
        ? 'Pair a new device (Source)'
        : 'Pair with existing identity (Target)';
    return Dialog(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 560, maxHeight: 720),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(20, 16, 8, 4),
              child: Row(
                children: [
                  Expanded(
                    child: Text(title,
                        style: Theme.of(context).textTheme.titleLarge),
                  ),
                  IconButton(
                    icon: const Icon(Icons.close),
                    onPressed: () => Navigator.of(context).pop(false),
                  ),
                ],
              ),
            ),
            _buildStepIndicator(),
            if (_error != null) _buildErrorBanner(),
            Flexible(
              child: SingleChildScrollView(
                padding: const EdgeInsets.all(16),
                child: widget.role == PairingRole.source
                    ? _buildSourceStep()
                    : _buildTargetStep(),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildStepIndicator() {
    final steps = widget.role == PairingRole.source
        ? ['Password', 'Show URI', 'Process Hello', 'Process Confirm']
        : ['Scan URI', 'Show Hello', 'Compare OOB', 'Done'];
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 8),
      child: Row(
        children: [
          for (int i = 0; i < steps.length; i++) ...[
            CircleAvatar(
              radius: 12,
              backgroundColor: i <= _step
                  ? Theme.of(context).colorScheme.primary
                  : Theme.of(context).colorScheme.surfaceContainerHighest,
              child: Text('${i + 1}',
                  style: TextStyle(
                      fontSize: 12,
                      color: i <= _step
                          ? Theme.of(context).colorScheme.onPrimary
                          : Theme.of(context).colorScheme.onSurface)),
            ),
            if (i < steps.length - 1)
              Expanded(
                  child: Container(
                      height: 2,
                      color: i < _step
                          ? Theme.of(context).colorScheme.primary
                          : Theme.of(context)
                              .colorScheme
                              .surfaceContainerHighest)),
          ],
        ],
      ),
    );
  }

  Widget _buildErrorBanner() {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
      color: Theme.of(context).colorScheme.errorContainer,
      child: Text(_error!,
          style: TextStyle(color: Theme.of(context).colorScheme.onErrorContainer)),
    );
  }

  // ── Source flow ──────────────────────────────────────────────────

  Widget _buildSourceStep() {
    switch (_step) {
      case 0:
        return _sourceStep0Password();
      case 1:
        return _sourceStep1ShowUri();
      case 2:
        return _sourceStep2ProcessHello();
      case 3:
        return _sourceStep3ProcessConfirm();
      default:
        return _doneCard('Paired successfully');
    }
  }

  Widget _sourceStep0Password() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Text(
          'Enter the master passphrase to decrypt `master.enc`.  This is '
          'the passphrase you set when running `identity create` or restoring '
          'from BIP-39 phrase.',
        ),
        const SizedBox(height: 12),
        TextField(
          controller: _masterPasswordCtl,
          obscureText: true,
          decoration: const InputDecoration(
            border: OutlineInputBorder(),
            labelText: 'Master passphrase',
          ),
          onSubmitted: (_) => _onSourceGenerateInvite(),
        ),
        const SizedBox(height: 12),
        FilledButton.icon(
          icon: const Icon(Icons.qr_code_2),
          label: const Text('Generate invite'),
          onPressed: _busy ? null : _onSourceGenerateInvite,
        ),
      ],
    );
  }

  Widget _sourceStep1ShowUri() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Text(
          'Show this QR to the target device (or paste the URI).  Target '
          'will send back a Hello byte string — paste it in the next step.',
        ),
        const SizedBox(height: 12),
        Center(
          child: Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Colors.white,
              borderRadius: BorderRadius.circular(8),
              border: Border.all(
                  color: Theme.of(context).colorScheme.outline),
            ),
            child: QrImageView(
              data: _pairingUri ?? '',
              version: QrVersions.auto,
              size: 220,
              errorCorrectionLevel: QrErrorCorrectLevel.M,
            ),
          ),
        ),
        const SizedBox(height: 8),
        SelectableText(_pairingUri ?? '',
            style: const TextStyle(fontFamily: 'monospace', fontSize: 11)),
        const SizedBox(height: 8),
        Row(
          children: [
            TextButton.icon(
              icon: const Icon(Icons.copy),
              label: const Text('Copy URI'),
              onPressed: () async {
                if (_pairingUri == null) return;
                await Clipboard.setData(ClipboardData(text: _pairingUri!));
              },
            ),
            const Spacer(),
            FilledButton(
              onPressed: () => setState(() => _step = 2),
              child: const Text('Next: paste Hello'),
            ),
          ],
        ),
      ],
    );
  }

  Widget _sourceStep2ProcessHello() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Text('Paste the Hello bytes (hex string) the target showed:'),
        const SizedBox(height: 8),
        TextField(
          controller: _helloBytesCtl,
          maxLines: 5,
          style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
          decoration: const InputDecoration(
            border: OutlineInputBorder(),
            hintText: 'a3f8b2...',
          ),
        ),
        const SizedBox(height: 12),
        FilledButton(
          onPressed: _busy ? null : _onSourceProcessHello,
          child: const Text('Process Hello'),
        ),
        if (_sourceOob != null) ...[
          const SizedBox(height: 16),
          _oobBlock('Source OOB code (compare with target screen):', _sourceOob!),
          const SizedBox(height: 12),
          const Text('Cert bytes to send to target:'),
          const SizedBox(height: 4),
          _hexBlock(_certBytes!),
          const SizedBox(height: 12),
          FilledButton(
            onPressed: () => setState(() => _step = 3),
            child: const Text('Next: paste Confirm'),
          ),
        ],
      ],
    );
  }

  Widget _sourceStep3ProcessConfirm() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Text('Paste the Confirm bytes the target showed:'),
        const SizedBox(height: 8),
        TextField(
          controller: _confirmBytesCtl,
          maxLines: 5,
          style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
          decoration: const InputDecoration(border: OutlineInputBorder()),
        ),
        const SizedBox(height: 12),
        FilledButton(
          onPressed: _busy ? null : _onSourceProcessConfirm,
          child: const Text('Finalize pairing'),
        ),
      ],
    );
  }

  Future<void> _onSourceGenerateInvite() async {
    if (_masterPasswordCtl.text.trim().isEmpty) {
      setState(() => _error = 'Passphrase cannot be empty');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final r = await widget.client.pairSourceCreateInvite(
        password: _masterPasswordCtl.text,
      );
      if (r.status == PairSourceStatus.ok) {
        setState(() {
          _pairingUri = r.uri;
          _step = 1;
        });
      } else {
        setState(() => _error = '${r.status.name}: ${r.detail ?? "no detail"}');
      }
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _onSourceProcessHello() async {
    final hello = _decodeHexOrError(_helloBytesCtl.text);
    if (hello == null) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final r =
          await widget.client.pairSourceHandleHello(helloBytes: hello);
      final status = PairSourceStatus.fromWire(r.statusByte);
      if (status == PairSourceStatus.ok) {
        setState(() {
          _certBytes = r.responseBytes;
          _sourceOob = r.oobCode;
        });
      } else {
        setState(() => _error = '${status.name}: ${r.detail ?? "no detail"}');
      }
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _onSourceProcessConfirm() async {
    final confirm = _decodeHexOrError(_confirmBytesCtl.text);
    if (confirm == null) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final r = await widget.client
          .pairSourceHandleConfirm(confirmBytes: confirm);
      if (!mounted) return;
      if (r.status == PairSourceStatus.ok) {
        Navigator.of(context).pop(true);
      } else {
        setState(() => _error = '${r.status.name}: ${r.detail ?? "no detail"}');
      }
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  // ── Target flow ──────────────────────────────────────────────────

  Widget _buildTargetStep() {
    switch (_step) {
      case 0:
        return _targetStep0Uri();
      case 1:
        return _targetStep1ShowHello();
      case 2:
        return _targetStep2CompareOob();
      case 3:
        return _targetStep3ShowConfirm();
      default:
        return _doneCard('Paired successfully');
    }
  }

  Widget _targetStep0Uri() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Text('Paste the pairing URI shown by the source device:'),
        const SizedBox(height: 8),
        TextField(
          controller: _uriPasteCtl,
          maxLines: 3,
          style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
          decoration: const InputDecoration(
            border: OutlineInputBorder(),
            hintText: 'veil:pair?…',
          ),
        ),
        const SizedBox(height: 12),
        FilledButton(
          onPressed: _busy ? null : _onTargetConsumeUri,
          child: const Text('Consume URI'),
        ),
      ],
    );
  }

  Widget _targetStep1ShowHello() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Text('Hello bytes to send to source (paste these in source screen):'),
        const SizedBox(height: 8),
        _hexBlock(_helloBytes!),
        const SizedBox(height: 16),
        const Text('Then paste the Cert bytes source sends back:'),
        const SizedBox(height: 8),
        TextField(
          controller: _certBytesCtl,
          maxLines: 5,
          style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
          decoration: const InputDecoration(border: OutlineInputBorder()),
        ),
        const SizedBox(height: 12),
        FilledButton(
          onPressed: _busy ? null : _onTargetProcessCert,
          child: const Text('Process Cert'),
        ),
      ],
    );
  }

  Widget _targetStep2CompareOob() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _oobBlock(
          'Target OOB code — does it match source\'s screen?',
          _targetOob!,
        ),
        const SizedBox(height: 16),
        Row(
          children: [
            Expanded(
              child: OutlinedButton.icon(
                icon: const Icon(Icons.cancel),
                label: const Text('No match — abort'),
                onPressed:
                    _busy ? null : () => _onTargetBuildConfirm(false),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: FilledButton.icon(
                icon: const Icon(Icons.check),
                label: const Text('Codes match'),
                onPressed:
                    _busy ? null : () => _onTargetBuildConfirm(true),
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _targetStep3ShowConfirm() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Text('Send these Confirm bytes back to source:'),
        const SizedBox(height: 8),
        _hexBlock(_confirmBytesOut!),
        const SizedBox(height: 16),
        Text(
          'Once source processes the Confirm, both devices share the same '
          'identity.  This device persisted a new subkey to disk.',
          style: Theme.of(context).textTheme.bodySmall,
        ),
        const SizedBox(height: 12),
        FilledButton(
          onPressed: () => Navigator.of(context).pop(true),
          child: const Text('Done'),
        ),
      ],
    );
  }

  Future<void> _onTargetConsumeUri() async {
    if (_uriPasteCtl.text.trim().isEmpty) {
      setState(() => _error = 'URI cannot be empty');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final r =
          await widget.client.pairTargetConsumeUri(uri: _uriPasteCtl.text.trim());
      if (r.status == PairTargetStatus.ok) {
        setState(() {
          _helloBytes = r.bytes;
          _step = 1;
        });
      } else {
        setState(() => _error = '${r.status.name}: ${r.detail ?? "no detail"}');
      }
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _onTargetProcessCert() async {
    final cert = _decodeHexOrError(_certBytesCtl.text);
    if (cert == null) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final r = await widget.client.pairTargetHandleCert(certBytes: cert);
      final status = PairTargetStatus.fromWire(r.statusByte);
      if (status == PairTargetStatus.ok) {
        setState(() {
          _targetOob = r.oobCode;
          _step = 2;
        });
      } else {
        setState(() => _error = '${status.name}: ${r.detail ?? "no detail"}');
      }
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _onTargetBuildConfirm(bool confirmed) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final r =
          await widget.client.pairTargetBuildConfirm(confirmed: confirmed);
      if (!mounted) return;
      if (r.status == PairTargetStatus.ok) {
        if (confirmed) {
          setState(() {
            _confirmBytesOut = r.bytes;
            _step = 3;
          });
        } else {
          Navigator.of(context).pop(false);
        }
      } else {
        setState(() => _error = '${r.status.name}: ${r.detail ?? "no detail"}');
      }
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  // ── Helpers ──────────────────────────────────────────────────────

  Widget _oobBlock(String label, String code) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.primaryContainer,
        borderRadius: BorderRadius.circular(12),
      ),
      child: Column(
        children: [
          Text(label,
              style: TextStyle(
                  color: Theme.of(context).colorScheme.onPrimaryContainer)),
          const SizedBox(height: 8),
          Text(
            code,
            style: TextStyle(
              fontSize: 32,
              fontFamily: 'monospace',
              letterSpacing: 8,
              fontWeight: FontWeight.bold,
              color: Theme.of(context).colorScheme.onPrimaryContainer,
            ),
          ),
        ],
      ),
    );
  }

  Widget _hexBlock(Uint8List bytes) {
    final hex = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: Theme.of(context).colorScheme.surfaceContainerHighest,
            borderRadius: BorderRadius.circular(8),
          ),
          constraints: const BoxConstraints(maxHeight: 100),
          child: SingleChildScrollView(
            child: SelectableText(
              hex,
              style:
                  const TextStyle(fontFamily: 'monospace', fontSize: 11),
            ),
          ),
        ),
        const SizedBox(height: 4),
        Row(
          mainAxisAlignment: MainAxisAlignment.end,
          children: [
            TextButton.icon(
              icon: const Icon(Icons.copy),
              label: Text('Copy (${bytes.length} B)'),
              onPressed: () async {
                await Clipboard.setData(ClipboardData(text: hex));
              },
            ),
          ],
        ),
      ],
    );
  }

  Widget _doneCard(String message) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          children: [
            Icon(Icons.check_circle,
                size: 64, color: Theme.of(context).colorScheme.primary),
            const SizedBox(height: 16),
            Text(message,
                style: Theme.of(context).textTheme.titleLarge),
          ],
        ),
      ),
    );
  }

  /// Decode user-pasted hex string; returns null + sets _error if bad.
  Uint8List? _decodeHexOrError(String input) {
    final cleaned = input.replaceAll(RegExp(r'\s+'), '').toLowerCase();
    if (cleaned.isEmpty || cleaned.length.isOdd) {
      setState(() => _error = 'Hex input must be non-empty and even-length');
      return null;
    }
    try {
      final out = Uint8List(cleaned.length ~/ 2);
      for (int i = 0; i < out.length; i++) {
        out[i] = int.parse(cleaned.substring(i * 2, i * 2 + 2), radix: 16);
      }
      return out;
    } catch (e) {
      setState(() => _error = 'Bad hex: $e');
      return null;
    }
  }
}

