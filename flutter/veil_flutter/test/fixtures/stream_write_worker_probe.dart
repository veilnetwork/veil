import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:veil_flutter/src/bindings.dart' as ffi;
import 'package:veil_flutter/src/stream.dart';
import 'package:veil_flutter/src/types.dart';

Future<void> main() async {
  final native = DynamicLibrary.open(Platform.environment['VEIL_FFI_DYLIB']!);
  final entered = native.lookupFunction<Int32 Function(), int Function()>(
    'stream_test_entered',
  );
  final order = native.lookupFunction<Int32 Function(), int Function()>(
    'stream_test_order',
  );
  final release = native.lookupFunction<Void Function(), void Function()>(
    'stream_test_release',
  );
  final stream = VeilStream.fromFfi(Pointer<ffi.VeilStreamFfi>.fromAddress(1));
  var ticks = 0;
  var released = false;
  final timer = Timer.periodic(const Duration(milliseconds: 10), (_) {
    ticks++;
    if (entered() > 0) {
      released = true;
      release();
    }
  });
  try {
    await Future.wait([
      stream.write(Uint8List.fromList([1])),
      stream.write(Uint8List.fromList([2])),
      stream.write(Uint8List.fromList([3])),
    ]);
    if (!released || ticks == 0 || order() != 123) {
      throw StateError('event loop stopped or stream bytes reordered');
    }
    await stream.close();
    try {
      await stream.write(Uint8List.fromList([4]));
      throw StateError('write after close was accepted');
    } on VeilException {
      // Closed handles never reach the native writer.
    }
    if (entered() != 3) throw StateError('closed write reached native code');
    stdout.writeln('responsive event loop, FIFO bytes, closed write rejected');
  } finally {
    timer.cancel();
    release();
    await stream.close();
  }
}
