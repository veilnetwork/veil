// Pure-Dart unit tests for the push-envelope sealing primitive +
// status code constants (Epic 489.10).  Native FFI sealing requires
// the daemon `.so` to be loaded — those tests run in the integration
// suite on CI with the mobile-build artifacts.

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:veil_flutter/veil_flutter.dart';

void main() {
  group('Push public exports', () {
    test('VeilPush resolves through root', () {
      const t = VeilPush;
      expect(t.toString(), 'VeilPush');
    });

    test('drainMailbox signature is a Future<List<MailboxBlob>>', () {
      // Compile-time-only assertion via type inference: assigning to
      // `Future<List<MailboxBlob>> Function(...)` would fail on signature
      // drift.  Body is unreachable (test verifies the type, not runtime
      // — a real drain needs an open daemon).
      const Future<List<MailboxBlob>> Function({
        required String socketPath,
        required Uint8List receiverId,
        required Uint8List authCookie,
      }) drainFn = VeilPush.drainMailbox;
      expect(drainFn, isNotNull);
    });
  });

  group('WakePayloadVerdict wire mapping (slice 4.3.3)', () {
    test('fromWire maps all known verdict bytes', () {
      expect(WakePayloadVerdict.fromWire(0), WakePayloadVerdict.valid);
      expect(WakePayloadVerdict.fromWire(1), WakePayloadVerdict.tamperedOrForged);
      expect(WakePayloadVerdict.fromWire(2), WakePayloadVerdict.expired);
      expect(WakePayloadVerdict.fromWire(3), WakePayloadVerdict.malformedLength);
    });

    test('fromWire maps unknown bytes to unknown', () {
      expect(WakePayloadVerdict.fromWire(99), WakePayloadVerdict.unknown);
      expect(WakePayloadVerdict.fromWire(255), WakePayloadVerdict.unknown);
      expect(WakePayloadVerdict.fromWire(-1), WakePayloadVerdict.unknown);
    });

    test('canonical wire bytes match veilclient-ffi constants', () {
      expect(WakePayloadVerdict.valid.wireByte, 0);
      expect(WakePayloadVerdict.tamperedOrForged.wireByte, 1);
      expect(WakePayloadVerdict.expired.wireByte, 2);
      expect(WakePayloadVerdict.malformedLength.wireByte, 3);
    });
  });

  group('Wake-HMAC public surface (slice 4.3.3)', () {
    test('generateWakeHmacKey signature returns Uint8List', () {
      // Compile-time-only assertion — a real call needs the FFI lib loaded.
      const Uint8List Function() genFn = VeilPush.generateWakeHmacKey;
      expect(genFn, isNotNull);
    });

    test('sealWakeHmacKey signature accepts named key + relayPk', () {
      const Uint8List Function({required Uint8List key, required Uint8List relayPk})
          sealFn = VeilPush.sealWakeHmacKey;
      expect(sealFn, isNotNull);
    });

    test('verifyWakePayload signature returns WakePayloadVerdict', () {
      const WakePayloadVerdict Function({
        required Uint8List key,
        required Uint8List payload,
        required Uint8List receiverId,
        required int nowSecs,
      }) verifyFn = VeilPush.verifyWakePayload;
      expect(verifyFn, isNotNull);
    });
  });

  group('Push wake-HMAC end-to-end surface', () {
    test('handleWakeup signature carries the requireAuth fail-closed flag',
        () {
      // Compile-time-only assertion — pins the named-param set incl. the
      // new `requireAuth` gate.  Body unreachable (a real call needs the
      // FFI lib + push channel).
      const Future<void> Function({
        Future<void> Function()? onWake,
        Uint8List? wakePayload,
        Uint8List? wakeHmacKey,
        Uint8List? receiverId,
        bool requireAuth,
      }) wakeFn = VeilPush.handleWakeup;
      expect(wakeFn, isNotNull);
    });

    test('storeWakeHmacKey signature accepts a raw key', () {
      const Future<void> Function(Uint8List) storeFn =
          VeilPush.storeWakeHmacKey;
      expect(storeFn, isNotNull);
    });

    test('loadWakeHmacKey signature returns Future<Uint8List?>', () {
      const Future<Uint8List?> Function() loadFn = VeilPush.loadWakeHmacKey;
      expect(loadFn, isNotNull);
    });

    test('generateAndRegisterWakeHmacKey composes the onboarding flow', () {
      const Future<bool> Function({
        required VeilClient client,
        required Uint8List relayPk,
        required Uint8List rendezvousNodeId,
        required Uint8List authCookie,
      }) regFn = VeilPush.generateAndRegisterWakeHmacKey;
      expect(regFn, isNotNull);
    });
  });

  group('encodePushToken provider-tagged wire format (H12)', () {
    test('FCM token encodes [0][len BE][token]', () {
      final token = Uint8List.fromList([0xAA, 0xBB, 0xCC]);
      final wire = VeilPush.encodePushToken(
        provider: PushProvider.fcm,
        token: token,
      );
      expect(wire[0], 0, reason: 'FCM provider byte is 0');
      expect(wire[1], 0, reason: 'len high byte');
      expect(wire[2], 3, reason: 'len low byte (3)');
      expect(wire.sublist(3), token);
      expect(wire.length, 6);
    });

    test('APNs provider byte is 1', () {
      final wire = VeilPush.encodePushToken(
        provider: PushProvider.apns,
        token: Uint8List.fromList([0x01]),
      );
      expect(wire[0], 1);
    });

    test('provider wire bytes match the relay PushProvider enum', () {
      expect(PushProvider.fcm.wireByte, 0);
      expect(PushProvider.apns.wireByte, 1);
    });

    test('rejects a token whose tagged length exceeds the cap', () {
      // 3-byte header + token must stay within veilMaxPushTokenLen (384).
      final tooBig = Uint8List(384); // 3 + 384 = 387 > 384
      expect(
        () => VeilPush.encodePushToken(
          provider: PushProvider.fcm,
          token: tooBig,
        ),
        throwsArgumentError,
      );
    });

    test('empty token encodes a 3-byte header with zero length', () {
      final wire = VeilPush.encodePushToken(
        provider: PushProvider.fcm,
        token: Uint8List(0),
      );
      expect(wire, Uint8List.fromList([0, 0, 0]));
    });
  });
}
