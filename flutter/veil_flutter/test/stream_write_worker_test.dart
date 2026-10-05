import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:veil_flutter/src/abi_contract.dart' as abi;

void main() {
  test('blocked native stream write leaves Dart responsive and preserves FIFO',
      () async {
    final temp = await Directory.systemTemp.createTemp('veil-stream-worker-');
    try {
      final library =
          '${temp.path}/stream-worker.${Platform.isMacOS ? 'dylib' : 'so'}';
      final built = await Process.run('clang', [
        Platform.isMacOS ? '-dynamiclib' : '-shared',
        '-fPIC',
        '-pthread',
        '-DXVEIL_TEST_ABI_HASH="${abi.veilAbiContractHash}"',
        'test/fixtures/stream_write_blocking.c',
        '-o',
        library,
      ]);
      expect(built.exitCode, 0, reason: '${built.stderr}');
      final flutter = await Process.run('which', ['flutter']);
      expect(flutter.exitCode, 0);
      final sdk =
          File((flutter.stdout as String).trim()).resolveSymbolicLinksSync();
      final dart = '${File(sdk).parent.path}/cache/dart-sdk/bin/dart';
      final probe = await Process.run(dart, [
        '--packages=.dart_tool/package_config.json',
        'test/fixtures/stream_write_worker_probe.dart',
      ], environment: {
        'VEIL_FFI_DYLIB': library
      });
      expect(probe.exitCode, 0, reason: '${probe.stdout}\n${probe.stderr}');
      expect(probe.stdout, contains('responsive event loop, FIFO bytes'));
    } finally {
      await temp.delete(recursive: true);
    }
  },
      skip: !(Platform.isMacOS || Platform.isLinux),
      timeout: const Timeout(Duration(seconds: 30)));
}
