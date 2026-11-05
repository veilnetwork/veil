import 'dart:async';
import 'dart:ffi';
import 'dart:io';

import 'package:veil_flutter/src/client.dart';
import 'package:veil_flutter/src/types.dart';

Future<void> main(List<String> args) async {
  final mode = int.parse(args.single);
  final native = DynamicLibrary.open(Platform.environment['VEIL_FFI_DYLIB']!);
  int Function() read(String name) => native
      .lookupFunction<Int32 Function(), int Function()>('network_test_$name');
  final entered = read('entered'), completed = read('completed');
  final freed = read('freed'), kind = read('kind'), mtu = read('mtu');
  final release = native.lookupFunction<Void Function(), void Function()>(
    'network_test_release',
  );
  native.lookupFunction<Void Function(Int32), void Function(int)>(
    'network_test_mode',
  )(mode);
  final client = await VeilClient.connect('controlled-stand');
  // The live NativeCallable cannot be sent to a worker. Only the opaque
  // integer token and scalar arguments may cross the isolate boundary.
  final subscription = client.events().listen((_) {});
  var released = false, finishedEarly = false;
  var returned = false;
  Future<void>? closing;
  final timer = Timer.periodic(const Duration(milliseconds: 10), (_) {
    if (entered() == 0 || released) return;
    finishedEarly = returned || completed() != 0;
    released = true;
    if (mode == 2) closing = client.close();
    release();
  });
  try {
    VeilException? failure;
    try {
      await client.notifyNetworkChanged(NetworkKind.cellular, mtuHint: 1320);
      returned = true;
    } on VeilException catch (error) {
      failure = error;
    }
    if (!released || finishedEarly || completed() != 1 || entered() != 1) {
      throw StateError(
          'network notification blocked its event loop or completed early');
    }
    if (kind() != NetworkKind.cellular.wireByte || mtu() != 1320) {
      throw StateError('network arguments changed');
    }
    if (mode == 0 ? failure != null : failure?.code != -1) {
      throw StateError('native dispatch result was lost');
    }
    if (freed() != (mode == 0 ? 0 : 1)) {
      throw StateError('native error ownership changed');
    }
    await closing;
    await client.close();
    try {
      await client.notifyNetworkChanged(NetworkKind.wifi);
      throw StateError('closed client was accepted');
    } on VeilException {
      // No second native call is permitted after close.
    }
    if (entered() != 1) throw StateError('closed notification reached native');
    stdout.writeln(
        'responsive event loop, dispatch barrier, native outcome and close');
  } finally {
    timer.cancel();
    release();
    await closing;
    await client.close();
    await subscription.cancel();
  }
}
