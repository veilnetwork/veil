import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:veil_media/veil_media.dart';

void check(bool value, String reason) {
  if (!value) throw StateError(reason);
}

void main() {
  test('native microphone refusal, retry, mute and disposal', () {
    final native =
        DynamicLibrary.open(Platform.environment['VEIL_MEDIA_DYLIB']!);
    final allow = native.lookupFunction<Void Function(), void Function()>(
        'stand_allow_capture');
    final last = native
        .lookupFunction<Int32 Function(), int Function()>('stand_last_muted');
    final engine = VeilMediaEngine.create(
        veilChan: 1, localId: Uint8List(32), peerId: Uint8List(32))!;
    check(!engine.trySetMicMuted(false), 'refused capture must return false');
    check(last() == 0, 'unmute must reach native');
    check(engine.trySetMicMuted(true), 'capture refusal must not prevent mute');
    allow();
    check(engine.trySetMicMuted(false),
        'later successful capture must return true');
    engine.setMicMuted(true); // Existing void API remains usable.
    check(last() == 1, 'legacy mute must still reach native');
    engine.dispose();
    var closed = false;
    try {
      engine.trySetMicMuted(false);
    } on StateError {
      closed = true;
    }
    check(closed, 'disposed engines must not reach native');
  });
}
