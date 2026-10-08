import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:veil_flutter/src/bindings.dart' as ffi;
import 'package:veil_flutter/src/stream.dart';
import 'package:veil_flutter/src/types.dart';

Future<void> main() async {
  final native = DynamicLibrary.open(Platform.environment['VEIL_FFI_DYLIB']!);
  final mode = native.lookupFunction<Void Function(), void Function()>(
      'stream_test_progress_mode');
  final permit = native
      .lookupFunction<Void Function(), void Function()>('stream_test_permit');
  final release = native
      .lookupFunction<Void Function(), void Function()>('stream_test_release');
  final total = native
      .lookupFunction<Int32 Function(), int Function()>('stream_test_total');
  final checksum = native.lookupFunction<Uint32 Function(), int Function()>(
      'stream_test_checksum');
  final finished = native.lookupFunction<Int32 Function(), int Function()>(
      'stream_test_finished_total');
  final failAfter =
      native.lookupFunction<Void Function(Int32), void Function(int)>(
          'stream_test_fail_after');
  final data = Uint8List.fromList(List.generate(25001, (n) => n % 251));
  final tail = Uint8List.fromList([253, 254, 255]);
  final expected = [...data, ...tail]
      .fold<int>(0, (hash, byte) => (hash * 31 + byte) & 0xffffffff);
  for (final anonymous in [false, true]) {
    mode();
    final direct =
        VeilStream.fromFfi(Pointer<ffi.VeilStreamFfi>.fromAddress(1));
    final anon =
        VeilAnonStream.fromFfi(Pointer<ffi.VeilAnonStreamFfi>.fromAddress(2));
    final observed = <int>[];
    var ticks = 0;
    final timer = Timer.periodic(const Duration(milliseconds: 20), (_) {
      ticks++;
      permit();
    });
    // Capture the Finalizable direct wrapper deliberately: the observer must
    // remain on this isolate, even while its write is on a worker.
    void progress(int bytes) {
      if (direct.hashCode == 0) throw StateError('unreachable');
      observed.add(bytes);
    }

    try {
      if (anonymous) {
        await Future.wait([
          anon.write(data, onProgress: progress),
          anon.write(tail),
          anon.finish()
        ]);
        if (finished() != data.length + tail.length)
          throw StateError('FIN overtook data');
      } else {
        await Future.wait(
            [direct.write(data, onProgress: progress), direct.write(tail)]);
      }
      if (ticks < 3 || observed.length < 3 || observed.last != data.length) {
        throw StateError('intermediate native progress missing or UI blocked');
      }
      if (total() != data.length + tail.length || checksum() != expected) {
        throw StateError('write bytes lost, duplicated or interleaved');
      }
      for (var i = 1; i < observed.length; i++) {
        if (observed[i] <= observed[i - 1])
          throw StateError('nonmonotonic progress');
      }
    } finally {
      timer.cancel();
      release();
      await direct.close();
      await anon.close();
    }
  }
  for (final anonymous in [false, true]) {
    mode();
    failAfter(7800);
    final direct =
        VeilStream.fromFfi(Pointer<ffi.VeilStreamFfi>.fromAddress(1));
    final anon =
        VeilAnonStream.fromFfi(Pointer<ffi.VeilAnonStreamFfi>.fromAddress(2));
    final observed = <int>[];
    final timer =
        Timer.periodic(const Duration(milliseconds: 20), (_) => permit());
    try {
      try {
        if (anonymous) {
          await anon.write(data, onProgress: observed.add);
        } else {
          await direct.write(data, onProgress: observed.add);
        }
        throw StateError('native write failure hidden');
      } on VeilException {
        if (total() != 7800 || observed.any((count) => count > 7800)) {
          throw StateError('failed suffix sent or reported as admitted');
        }
      }
    } finally {
      timer.cancel();
      release();
      await direct.close();
      await anon.close();
    }
  }
  stdout.writeln('native progress, responsive UI, FIFO bytes and FIN');
}
