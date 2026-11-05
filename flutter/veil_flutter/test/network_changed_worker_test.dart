import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:veil_flutter/src/abi_contract.dart' as abi;

void main() {
  for (final mode in [0, 1, 2]) {
    test('network dispatch leaves Dart responsive, native outcome=$mode',
        () async {
      final temp =
          await Directory.systemTemp.createTemp('veil-network-worker-');
      try {
        final library =
            '${temp.path}/network-worker.${Platform.isMacOS ? 'dylib' : 'so'}';
        final build = await Process.run('clang', [
          Platform.isMacOS ? '-dynamiclib' : '-shared',
          '-fPIC',
          '-pthread',
          '-DXVEIL_TEST_ABI_HASH="${abi.veilAbiContractHash}"',
          'test/fixtures/network_changed_blocking.c',
          '-o',
          library,
        ]);
        expect(build.exitCode, 0, reason: '${build.stderr}');
        final flutter = await Process.run('which', ['flutter']);
        expect(flutter.exitCode, 0);
        final sdk =
            File((flutter.stdout as String).trim()).resolveSymbolicLinksSync();
        final dart = '${File(sdk).parent.path}/cache/dart-sdk/bin/dart';
        final probe = await Process.run(dart, [
          '--packages=.dart_tool/package_config.json',
          'test/fixtures/network_changed_worker_probe.dart',
          '$mode',
        ], environment: {
          'VEIL_FFI_DYLIB': library
        });
        expect(probe.exitCode, 0, reason: '${probe.stdout}\n${probe.stderr}');
        expect(
            probe.stdout,
            contains(
                'responsive event loop, dispatch barrier, native outcome and close'));
      } finally {
        await temp.delete(recursive: true);
      }
    },
        skip: !(Platform.isMacOS || Platform.isLinux),
        timeout: const Timeout(Duration(seconds: 30)));
  }
}
