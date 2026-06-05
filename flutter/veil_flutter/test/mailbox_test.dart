// Pure-Dart unit tests для the mailbox wrapper's wire-byte mapping +
// public-API exports.  Live-daemon I/O tests belong к the integration
// suite (separate, requires а running `veil-cli daemon`).

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:veil_flutter/veil_flutter.dart';

void main() {
  group('MailboxPutStatus wire byte mapping', () {
    test('all known statuses round-trip from their wire byte', () {
      for (final s in MailboxPutStatus.values) {
        if (s == MailboxPutStatus.unknown) continue;
        expect(
          MailboxPutStatus.fromWire(s.wireByte),
          s,
          reason: 'wire byte ${s.wireByte} must decode к $s',
        );
      }
    });

    test('canonical wire bytes match veil_proto', () {
      // Mirrors veil_proto::MailboxPutStatus byte assignments.
      expect(MailboxPutStatus.stored.wireByte, 0);
      expect(MailboxPutStatus.duplicate.wireByte, 1);
      expect(MailboxPutStatus.quotaPerReceiver.wireByte, 2);
      expect(MailboxPutStatus.quotaGlobal.wireByte, 3);
      expect(MailboxPutStatus.rateLimited.wireByte, 4);
      expect(MailboxPutStatus.notRelay.wireByte, 5);
      expect(MailboxPutStatus.capabilityRequired.wireByte, 6);
      expect(MailboxPutStatus.capabilityInvalid.wireByte, 7);
      expect(MailboxPutStatus.quotaPerSender.wireByte, 8);
    });

    test('unknown wire byte yields MailboxPutStatus.unknown', () {
      // 99 is intentionally out of range — forward-compat path.
      expect(MailboxPutStatus.fromWire(99), MailboxPutStatus.unknown);
      // Negative is also unknown (real daemon never emits negative
      // status — those are transport errors at the FFI layer).
      expect(MailboxPutStatus.fromWire(-7), MailboxPutStatus.unknown);
    });
  });

  group('MailboxPutResult', () {
    test('stores status + evicted', () {
      const r = MailboxPutResult(
        status: MailboxPutStatus.stored,
        evicted: 3,
      );
      expect(r.status, MailboxPutStatus.stored);
      expect(r.evicted, 3);
      expect(r.toString(),
          'MailboxPutResult(status=MailboxPutStatus.stored, evicted=3)');
    });
  });

  group('Mailbox public exports', () {
    test('VeilMailbox + MailboxBlob types resolve through public API',
        () {
      // Smoke check: types are exported и compile-resolvable.
      const t1 = VeilMailbox;
      const t2 = MailboxBlob;
      const t3 = MailboxPutResult;
      const t4 = MailboxPutStatus;
      expect(t1.toString(), 'VeilMailbox');
      expect(t2.toString(), 'MailboxBlob');
      expect(t3.toString(), 'MailboxPutResult');
      expect(t4.toString(), 'MailboxPutStatus');
    });
  });

  group('Push wake-HMAC end-to-end surface', () {
    test('RendezvousReplica is exported и holds the per-replica blobs', () {
      final r = RendezvousReplica(
        relayNodeId: Uint8List(32),
        validUntilUnix: 1717000000,
        pushEnvelope: Uint8List.fromList([1, 2, 3]),
        capabilityToken: Uint8List.fromList([4, 5]),
        wakeHmacEnvelope: Uint8List.fromList([6, 7, 8, 9]),
      );
      expect(r.relayNodeId.length, 32);
      expect(r.validUntilUnix, 1717000000);
      expect(r.pushEnvelope, [1, 2, 3]);
      expect(r.capabilityToken, [4, 5]);
      expect(r.wakeHmacEnvelope, [6, 7, 8, 9]);
    });

    test('put exposes the optional wakeHmacEnvelope param', () {
      // Compile-time-only assertion: pins the instance-method named-param
      // set incl. the new `wakeHmacEnvelope`.  The closure is never
      // invoked (a real PUT needs an open daemon) — type-checked only.
      Future<MailboxPutResult> Function() pin(VeilMailbox m) => () => m.put(
            receiverId: Uint8List(32),
            contentId: Uint8List(32),
            senderId: Uint8List(32),
            blob: Uint8List(0),
            pushEnvelope: null,
            capabilityToken: null,
            wakeHmacEnvelope: Uint8List(0),
          );
      expect(pin, isNotNull);
    });

    test('lookupRendezvousReplicas signature returns the replica list', () {
      // Compile-time-only assertion on the instance-method shape.
      Future<List<RendezvousReplica>> Function() pin(VeilMailbox m) =>
          () => m.lookupRendezvousReplicas(Uint8List(32), maxReplicas: 3);
      expect(pin, isNotNull);
    });
  });
}
