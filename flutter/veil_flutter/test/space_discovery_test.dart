import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:veil_flutter/veil_flutter.dart';

Uint8List _buffer(List<List<int>> records) {
  final bytes = BytesBuilder(copy: false);
  void addU32(int value) {
    final data = ByteData(4)..setUint32(0, value, Endian.little);
    bytes.add(data.buffer.asUint8List());
  }

  addU32(records.length);
  for (final record in records) {
    addU32(record.length);
    bytes.add(record);
  }
  return bytes.toBytes();
}

void main() {
  test('decodes bounded length-prefixed discovery replicas', () {
    final decoded = decodeSpaceDiscoveryReplicaBuffer(
      _buffer([
        [1, 2, 3],
        [4, 5],
      ]),
    );
    expect(decoded, [
      Uint8List.fromList([1, 2, 3]),
      Uint8List.fromList([4, 5]),
    ]);
  });

  test('rejects truncation, excess count, oversized and trailing bytes', () {
    expect(
      () => decodeSpaceDiscoveryReplicaBuffer(Uint8List(3)),
      throwsFormatException,
    );
    expect(
      () => decodeSpaceDiscoveryReplicaBuffer(_buffer(List.filled(6, [1]))),
      throwsFormatException,
    );
    final oversizedHeader = ByteData(8)
      ..setUint32(0, 1, Endian.little)
      ..setUint32(4, 17 * 1024 + 1, Endian.little);
    expect(
      () => decodeSpaceDiscoveryReplicaBuffer(
        oversizedHeader.buffer.asUint8List(),
      ),
      throwsFormatException,
    );
    expect(
      () => decodeSpaceDiscoveryReplicaBuffer(
        Uint8List.fromList([..._buffer(const []), 0]),
      ),
      throwsFormatException,
    );
  });
}
