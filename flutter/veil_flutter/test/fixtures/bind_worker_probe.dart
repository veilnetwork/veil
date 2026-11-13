import 'dart:async';
import 'dart:ffi';
import 'dart:io';

import 'package:veil_flutter/src/client.dart';
import 'package:veil_flutter/src/types.dart';

Future<void> main(List<String> args) async {
  final binding = args[0], mode = int.parse(args[1]);
  final succeeds = mode == 0 || mode == 3;
  final variant = ['ephemeral', 'named', 'device'].indexOf(binding);
  if (variant < 0) throw ArgumentError('unknown binding');
  final native = DynamicLibrary.open(Platform.environment['VEIL_FFI_DYLIB']!);
  int Function() read(String name) => native
      .lookupFunction<Int32 Function(), int Function()>('bind_test_$name');
  final entered = read('entered'), completed = read('completed');
  final freed = read('freed'), closed = read('closed');
  final appClosed = read('app_closed');
  final release = native.lookupFunction<Void Function(), void Function()>(
    'bind_test_release',
  );
  native.lookupFunction<Void Function(Int32), void Function(int)>(
    'bind_test_mode',
  )(mode);
  final client = await VeilClient.connect('controlled-stand');
  // A live NativeCallable makes an accidental capture of the client unsendable.
  final subscription = client.events().listen((_) {});
  Future<AppHandle> bind() => switch (binding) {
        'named' => client.bindNamed(
            namespace: 'qa.namespace.λ',
            name: 'name.\u0442\u0435\u0441\u0442',
            endpointId: 0x12345678),
        'device' => client.bindDeviceScoped(
            namespace: 'qa.namespace.λ',
            name: 'name.\u0442\u0435\u0441\u0442',
            endpointId: 0x12345678),
        _ => client.bind(
            namespace: 'qa.namespace.λ',
            name: 'name.\u0442\u0435\u0441\u0442',
            endpointId: 0x12345678),
      };
  var released = false, finishedEarly = false, returned = false;
  Future<void>? closing;
  AppHandle? app;
  final timer = Timer.periodic(const Duration(milliseconds: 10), (_) {
    if (entered() == 0 || released) return;
    finishedEarly = returned || completed() != 0;
    released = true;
    if (mode >= 2) closing = client.close();
    release();
  });
  try {
    VeilException? failure;
    try {
      app = await bind();
      returned = true;
    } on VeilException catch (error) {
      failure = error;
    }
    if (!released || finishedEarly || completed() != 1 || entered() != 1) {
      throw StateError(
          'bind blocked its event loop or completed before release');
    }
    if (read('variant')() != variant || read('arguments_valid')() != 1) {
      throw StateError('bind variant or UTF-8 arguments changed');
    }
    if (succeeds) {
      if (failure != null || app == null || app.endpointId != 0x12345678) {
        throw StateError('native app result was lost');
      }
      for (var i = 0; i < 32; i++) {
        if (app.appId[i] != i + variant) throw StateError('app id changed');
      }
      await app.close();
      await app.close();
    } else if (app != null ||
        failure?.code != -1 ||
        failure?.message != 'bind failed: controlled bind refusal') {
      throw StateError('native bind failure was lost');
    }
    if (freed() != (succeeds ? 0 : 1) || appClosed() != (succeeds ? 1 : 0)) {
      throw StateError('bind error or app ownership changed');
    }
    await closing;
    await client.close();
    try {
      await bind();
      throw StateError('closed client was accepted');
    } on VeilException {
      // Rejected by the Dart owner before another native operation.
    }
    if (entered() != 1 || closed() != 1) {
      throw StateError('closed bind reached native or client closed twice');
    }
    stdout.writeln(
        'responsive bind, exact arguments, native outcome and ownership');
  } finally {
    timer.cancel();
    release();
    await app?.close();
    await closing;
    await client.close();
    await subscription.cancel();
  }
}
