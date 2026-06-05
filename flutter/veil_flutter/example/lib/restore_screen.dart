// BIP-39 identity restore screen (Epic 489.8 Flutter UI).
//
// Pure Material 3 widgets — no extra dependencies.  Drop into any
// app that uses veil_flutter; it produces the identity files and
// reports the path к the caller via the onRestored callback.
//
// Threat-model UX choices:
//   * Phrase entered as a single multiline TextField — copy-pasting
//     the 24 words from a password manager is easier than 24 small
//     fields, and Android/iOS clipboard sniffers see the same data
//     either way.
//   * Live word-count feedback ("18 / 24") so user knows when к stop.
//   * BIP-39 checksum check before showing "Restore" — surfaces
//     a typo immediately, not after a daemon round-trip.
//   * After restore, navigation is the caller's responsibility —
//     this widget just calls `onRestored(veilDir)`.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:veil_flutter/veil_flutter.dart';

class RestoreIdentityScreen extends StatefulWidget {
  const RestoreIdentityScreen({
    super.key,
    required this.veilDir,
    required this.onRestored,
    this.defaultInstanceLabel = '',
  });

  /// Where identity files are written.  Typically the app's
  /// `getApplicationSupportDirectory()` (path_provider).
  final String veilDir;

  /// Called on successful restore с the same [veilDir].  Caller
  /// typically navigates to "Connect" / "Home" screen and starts
  /// the daemon.
  final void Function(String veilDir) onRestored;

  /// Pre-fill the instance-label field (e.g. device model).
  final String defaultInstanceLabel;

  @override
  State<RestoreIdentityScreen> createState() => _RestoreIdentityScreenState();
}

class _RestoreIdentityScreenState extends State<RestoreIdentityScreen> {
  final _phraseCtrl = TextEditingController();
  late final TextEditingController _labelCtrl;
  String? _phraseError;
  String? _restoreError;
  bool _restoring = false;

  @override
  void initState() {
    super.initState();
    _labelCtrl = TextEditingController(text: widget.defaultInstanceLabel);
    _phraseCtrl.addListener(_revalidate);
  }

  @override
  void dispose() {
    _phraseCtrl.dispose();
    _labelCtrl.dispose();
    super.dispose();
  }

  /// Re-run lightweight validation as the user types.  Heavy BIP-39
  /// checksum check fires only when the word count is exactly 24,
  /// to avoid spurious "checksum invalid" while the user is still
  /// typing.
  void _revalidate() {
    final phrase = _phraseCtrl.text;
    if (!hasBip39WordCount(phrase)) {
      // Don't show errors during normal typing — only "too long" matters.
      final trimmed = phrase.trim().split(RegExp(r'\s+'))
          .where((w) => w.isNotEmpty).length;
      setState(() {
        _phraseError = trimmed > 24 ? 'too many words ($trimmed / 24)' : null;
      });
      return;
    }
    // Word count OK — verify checksum.
    try {
      validateBip39Phrase(phrase);
      setState(() => _phraseError = null);
    } on VeilException catch (e) {
      setState(() => _phraseError = e.message);
    }
  }

  bool get _canRestore =>
      hasBip39WordCount(_phraseCtrl.text) &&
      _phraseError == null &&
      _labelCtrl.text.trim().isNotEmpty &&
      !_restoring;

  Future<void> _doRestore() async {
    setState(() {
      _restoring = true;
      _restoreError = null;
    });
    try {
      // Off-isolate в case Argon2id (master-encryption file path —
      // currently unused here, но defensive) ever creeps in.
      // restoreIdentity itself is pure-compute under а second.
      await Future(() {
        restoreIdentity(
          phrase: _phraseCtrl.text,
          veilDir: widget.veilDir,
          instanceLabel: _labelCtrl.text.trim(),
        );
      });
      if (!mounted) return;
      widget.onRestored(widget.veilDir);
    } on VeilException catch (e) {
      if (!mounted) return;
      setState(() => _restoreError = e.message);
    } finally {
      if (mounted) setState(() => _restoring = false);
    }
  }

  int get _wordCount => _phraseCtrl.text.trim().split(RegExp(r'\s+'))
      .where((w) => w.isNotEmpty).length;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Restore identity')),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Enter your 24-word recovery phrase. Words are space-separated; '
              'order matters.',
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _phraseCtrl,
              maxLines: 5,
              autofocus: true,
              autocorrect: false,
              enableSuggestions: false,
              keyboardType: TextInputType.multiline,
              textCapitalization: TextCapitalization.none,
              inputFormatters: [
                // BIP-39 English wordlist is lowercase ASCII letters
                // + spaces / newlines.  Reject everything else early
                // so the user doesn't paste smart quotes / emoji.
                FilteringTextInputFormatter.allow(RegExp(r"[a-zA-Z\s]")),
              ],
              decoration: InputDecoration(
                border: const OutlineInputBorder(),
                hintText: 'word1 word2 word3 …',
                helperText: '$_wordCount / 24 words',
                errorText: _phraseError,
              ),
            ),
            const SizedBox(height: 16),
            const Text('Device label'),
            const SizedBox(height: 4),
            TextField(
              controller: _labelCtrl,
              maxLength: 64,
              decoration: const InputDecoration(
                border: OutlineInputBorder(),
                hintText: 'e.g. Phone — May 2024',
                helperText: 'Shown to your other devices.',
              ),
            ),
            if (_restoreError != null) ...[
              const SizedBox(height: 16),
              Material(
                color: Theme.of(context).colorScheme.errorContainer,
                borderRadius: BorderRadius.circular(8),
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Text(
                    _restoreError!,
                    style: TextStyle(
                      color: Theme.of(context).colorScheme.onErrorContainer,
                    ),
                  ),
                ),
              ),
            ],
            const SizedBox(height: 24),
            FilledButton.icon(
              onPressed: _canRestore ? _doRestore : null,
              icon: _restoring
                  ? const SizedBox(
                      height: 16, width: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.lock_open),
              label: Text(_restoring ? 'Restoring…' : 'Restore'),
            ),
            const SizedBox(height: 16),
            Text(
              'Identity files will be written to:\n${widget.veilDir}',
              style: Theme.of(context).textTheme.bodySmall,
            ),
          ],
        ),
      ),
    );
  }
}
