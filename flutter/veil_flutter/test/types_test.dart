// Pure-Dart tests for `veil_flutter` types — no FFI required so these
// run on `dart test` without the Rust shared library or a connected
// veil daemon.

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:veil_flutter/veil_flutter.dart';

void main() {
  group('VeilEventKind', () {
    test('fromWire maps known bytes', () {
      expect(VeilEventKind.fromWire(0), VeilEventKind.sessionsChanged);
      expect(VeilEventKind.fromWire(1), VeilEventKind.mobileTierChanged);
      expect(VeilEventKind.fromWire(2), VeilEventKind.identityRotated);
      expect(VeilEventKind.fromWire(3), VeilEventKind.mailboxDrained);
    });

    test('fromWire maps unknown to VeilEventKind.unknown', () {
      expect(VeilEventKind.fromWire(99), VeilEventKind.unknown);
      expect(VeilEventKind.fromWire(255), VeilEventKind.unknown);
    });
  });

  group('VeilEvent helpers', () {
    test('sessionCount decodes BE u16', () {
      final ev = VeilEvent(
        kind: VeilEventKind.sessionsChanged,
        rawKind: 0,
        payload: Uint8List.fromList([0x00, 0x07]),
      );
      expect(ev.sessionCount, 7);
    });

    test('sessionCount decodes higher counts', () {
      final ev = VeilEvent(
        kind: VeilEventKind.sessionsChanged,
        rawKind: 0,
        payload: Uint8List.fromList([0x01, 0x2c]), // 300
      );
      expect(ev.sessionCount, 300);
    });

    test('sessionCount returns null for wrong kind', () {
      final ev = VeilEvent(
        kind: VeilEventKind.mobileTierChanged,
        rawKind: 1,
        payload: Uint8List.fromList([0x00, 0x07]),
      );
      expect(ev.sessionCount, isNull);
    });

    test('sessionCount returns null for too-short payload', () {
      final ev = VeilEvent(
        kind: VeilEventKind.sessionsChanged,
        rawKind: 0,
        payload: Uint8List.fromList([0x00]),
      );
      expect(ev.sessionCount, isNull);
    });

    test('tierAfterChange decodes valid tier byte', () {
      final ev = VeilEvent(
        kind: VeilEventKind.mobileTierChanged,
        rawKind: 1,
        payload: Uint8List.fromList([2]), // lowPower
      );
      expect(ev.tierAfterChange, MobileBackgroundMode.lowPower);
    });

    test('tierAfterChange returns null for unknown tier byte', () {
      final ev = VeilEvent(
        kind: VeilEventKind.mobileTierChanged,
        rawKind: 1,
        payload: Uint8List.fromList([99]),
      );
      expect(ev.tierAfterChange, isNull);
    });

    test('tierAfterChange returns null for wrong kind', () {
      final ev = VeilEvent(
        kind: VeilEventKind.sessionsChanged,
        rawKind: 0,
        payload: Uint8List.fromList([1]),
      );
      expect(ev.tierAfterChange, isNull);
    });

    test('drainedCount decodes BE u32 (small)', () {
      final ev = VeilEvent(
        kind: VeilEventKind.mailboxDrained,
        rawKind: 3,
        payload: Uint8List.fromList([0, 0, 0, 7]),
      );
      expect(ev.drainedCount, 7);
    });

    test('drainedCount decodes BE u32 (large)', () {
      final ev = VeilEvent(
        kind: VeilEventKind.mailboxDrained,
        rawKind: 3,
        payload: Uint8List.fromList([0x01, 0x00, 0x00, 0x00]), // 16_777_216
      );
      expect(ev.drainedCount, 16777216);
    });

    test('drainedCount returns null for wrong kind', () {
      final ev = VeilEvent(
        kind: VeilEventKind.sessionsChanged,
        rawKind: 0,
        payload: Uint8List.fromList([0, 0, 0, 7]),
      );
      expect(ev.drainedCount, isNull);
    });

    test('drainedCount returns null for too-short payload', () {
      final ev = VeilEvent(
        kind: VeilEventKind.mailboxDrained,
        rawKind: 3,
        payload: Uint8List.fromList([0, 0, 7]),
      );
      expect(ev.drainedCount, isNull);
    });
  });

  group('Wire byte constants', () {
    test('MobileBackgroundMode wire bytes match veil_proto', () {
      expect(MobileBackgroundMode.foreground.wireByte, 0);
      expect(MobileBackgroundMode.active.wireByte, 1);
      expect(MobileBackgroundMode.lowPower.wireByte, 2);
    });

    test('NetworkKind wire bytes match veil_proto', () {
      expect(NetworkKind.offline.wireByte, 0);
      expect(NetworkKind.wifi.wireByte, 1);
      expect(NetworkKind.cellular.wireByte, 2);
      expect(NetworkKind.ethernet.wireByte, 3);
      expect(NetworkKind.unknown.wireByte, 255);
    });

    test('SenderProvenance wire bytes match veil_proto', () {
      expect(SenderProvenance.claimed.wireByte, 0);
      expect(SenderProvenance.localIpc.wireByte, 1);
      expect(SenderProvenance.sessionPeer.wireByte, 2);
      expect(SenderProvenance.signed.wireByte, 3);
    });
  });

  // Audit X/V-01. veil now tells the app what stands behind a delivery's
  // `srcNodeId`; these pin the two properties an app's trust decisions rest on.
  group('SenderProvenance', () {
    test('fromWire maps known bytes', () {
      expect(SenderProvenance.fromWire(0), SenderProvenance.claimed);
      expect(SenderProvenance.fromWire(1), SenderProvenance.localIpc);
      expect(SenderProvenance.fromWire(2), SenderProvenance.sessionPeer);
      expect(SenderProvenance.fromWire(3), SenderProvenance.signed);
    });

    test('an unrecognised byte fails CLOSED to claimed, never up', () {
      // Deliberately not an `unknown` member: "I could not read the evidence"
      // and "there was no evidence" must lead to the same decision, or a
      // future level would arrive at an old build as something it can trust.
      for (final b in [4, 5, 42, 127, 128, 254, 255]) {
        expect(SenderProvenance.fromWire(b), SenderProvenance.claimed,
            reason: 'byte $b must read as claimed');
        expect(SenderProvenance.fromWire(b).isAuthenticated, isFalse);
      }
    });

    test('isAuthenticated is false for claimed alone', () {
      expect(SenderProvenance.claimed.isAuthenticated, isFalse);
      expect(SenderProvenance.localIpc.isAuthenticated, isTrue);
      expect(SenderProvenance.sessionPeer.isAuthenticated, isTrue);
      expect(SenderProvenance.signed.isAuthenticated, isTrue);
    });

    test('IncomingMessage defaults to claimed when nothing says otherwise', () {
      // A construction site that says nothing has verified nothing. The
      // default must be the one value that cannot be mistaken for proof.
      final msg = IncomingMessage(
        srcNodeId: Uint8List(32),
        srcAppId: Uint8List(32),
        data: Uint8List(0),
      );
      expect(msg.provenance, SenderProvenance.claimed);
      expect(msg.provenance.isAuthenticated, isFalse);
    });
  });
}
