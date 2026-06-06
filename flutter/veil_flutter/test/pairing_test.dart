// Pure-Dart unit tests for JoinBootstrapStatus wire-byte mapping +
// public-API exports of the pairing surface.  Widget integration tests
// (camera permission, QR-detect path) belong to a separate
// `integration_test/` suite.

import 'package:flutter_test/flutter_test.dart';
import 'package:veil_flutter/veil_flutter.dart';

void main() {
  group('JoinBootstrapStatus wire-byte mapping', () {
    test('all known statuses round-trip through fromWire', () {
      for (final s in JoinBootstrapStatus.values) {
        if (s == JoinBootstrapStatus.unknown) continue;
        expect(
          JoinBootstrapStatus.fromWire(s.wireByte),
          s,
          reason: 'wire byte ${s.wireByte} must decode to $s',
        );
      }
    });

    test('canonical wire bytes match veil_proto', () {
      expect(JoinBootstrapStatus.ok.wireByte, 0);
      expect(JoinBootstrapStatus.invalidUri.wireByte, 1);
      expect(JoinBootstrapStatus.passwordRequired.wireByte, 2);
      expect(JoinBootstrapStatus.passwordWrong.wireByte, 3);
      expect(JoinBootstrapStatus.signatureInvalid.wireByte, 4);
      expect(JoinBootstrapStatus.internalError.wireByte, 5);
      expect(JoinBootstrapStatus.alreadyRegistered.wireByte, 6);
    });

    test('unknown byte yields JoinBootstrapStatus.unknown', () {
      expect(JoinBootstrapStatus.fromWire(99), JoinBootstrapStatus.unknown);
      expect(JoinBootstrapStatus.fromWire(-1), JoinBootstrapStatus.unknown);
    });
  });

  group('Pairing public exports', () {
    test('VeilPairingDialog + JoinBootstrapResult resolve through root', () {
      const t1 = VeilPairingDialog;
      const t2 = JoinBootstrapResult;
      const t3 = JoinBootstrapStatus;
      expect(t1.toString(), 'VeilPairingDialog');
      expect(t2.toString(), 'JoinBootstrapResult');
      expect(t3.toString(), 'JoinBootstrapStatus');
    });
  });

  group('CreateBootstrapInviteStatus wire-byte mapping', () {
    test('all known statuses round-trip through fromWire', () {
      for (final s in CreateBootstrapInviteStatus.values) {
        if (s == CreateBootstrapInviteStatus.unknown) continue;
        expect(
          CreateBootstrapInviteStatus.fromWire(s.wireByte),
          s,
          reason: 'wire byte ${s.wireByte} must decode to $s',
        );
      }
    });

    test('canonical wire bytes match veil_proto', () {
      expect(CreateBootstrapInviteStatus.ok.wireByte, 0);
      expect(CreateBootstrapInviteStatus.notConfigured.wireByte, 1);
      expect(CreateBootstrapInviteStatus.badPassword.wireByte, 2);
      expect(CreateBootstrapInviteStatus.internalError.wireByte, 3);
    });

    test('unknown byte yields CreateBootstrapInviteStatus.unknown', () {
      expect(CreateBootstrapInviteStatus.fromWire(99),
          CreateBootstrapInviteStatus.unknown);
      expect(CreateBootstrapInviteStatus.fromWire(-1),
          CreateBootstrapInviteStatus.unknown);
    });
  });

  group('Share-invite public exports', () {
    test('VeilShareInviteDialog + CreateBootstrapInviteResult resolve', () {
      const t1 = VeilShareInviteDialog;
      const t2 = CreateBootstrapInviteResult;
      const t3 = CreateBootstrapInviteStatus;
      expect(t1.toString(), 'VeilShareInviteDialog');
      expect(t2.toString(), 'CreateBootstrapInviteResult');
      expect(t3.toString(), 'CreateBootstrapInviteStatus');
    });
  });
}
