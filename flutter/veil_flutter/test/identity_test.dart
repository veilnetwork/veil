// Pure-Dart tests for `veil_flutter` identity helpers — only the
// helpers that DON'T touch FFI run on `dart test` без the native lib.
//
// `validateBip39Phrase` and `restoreIdentity` are FFI-bound and
// covered by the Rust-side unit tests in
// `crates/veilclient-ffi/src/lib.rs::tests::epic489_8_*`.

import 'package:flutter_test/flutter_test.dart';
import 'package:veil_flutter/veil_flutter.dart';

void main() {
  group('hasBip39WordCount', () {
    test('returns true for exactly 24 space-separated tokens', () {
      final phrase = List.generate(24, (i) => 'w$i').join(' ');
      expect(hasBip39WordCount(phrase), isTrue);
    });

    test('returns false for 23 tokens (one short)', () {
      final phrase = List.generate(23, (i) => 'w$i').join(' ');
      expect(hasBip39WordCount(phrase), isFalse);
    });

    test('returns false for 25 tokens (one too many)', () {
      final phrase = List.generate(25, (i) => 'w$i').join(' ');
      expect(hasBip39WordCount(phrase), isFalse);
    });

    test('returns false for empty string', () {
      expect(hasBip39WordCount(''), isFalse);
      expect(hasBip39WordCount('   '), isFalse);
    });

    test('collapses multiple whitespace correctly', () {
      // Newlines + tabs + extra spaces shouldn't break the count.
      final phrase = List.generate(24, (i) => 'w$i').join('  \t  \n  ');
      expect(hasBip39WordCount(phrase), isTrue);
    });

    test('trims leading + trailing whitespace', () {
      final phrase = '  ${List.generate(24, (i) => 'w$i').join(' ')}\n  ';
      expect(hasBip39WordCount(phrase), isTrue);
    });
  });
}
