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
  });
}
