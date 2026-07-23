import 'dart:ffi';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.dart' as ffi;
import 'types.dart';

enum SpaceDiscoveryRouteKind { direct, search }

String _takeError(Pointer<Pointer<Utf8>> errorOut, int result) {
  final pointer = errorOut.value;
  final message = pointer == nullptr
      ? 'space discovery error $result'
      : pointer.toDartString();
  if (pointer != nullptr) ffi.veilFreeString(pointer);
  return message;
}

void publishSpaceDiscoveryRecord({
  required Uint8List selfNodeId,
  required Uint8List record,
}) {
  if (selfNodeId.length != 32) {
    throw VeilException('selfNodeId must be 32 bytes');
  }
  if (record.isEmpty || record.length > 17 * 1024) {
    throw VeilException('Space discovery record has invalid length');
  }
  final selfPointer = calloc<Uint8>(32);
  final recordPointer = calloc<Uint8>(record.length);
  final errorOut = calloc<Pointer<Utf8>>();
  try {
    selfPointer.asTypedList(32).setAll(0, selfNodeId);
    recordPointer.asTypedList(record.length).setAll(0, record);
    final result = ffi.veilSpaceDiscoveryPublish(
      selfPointer,
      recordPointer,
      record.length,
      errorOut,
    );
    if (result != ffi.veilOk) {
      throw VeilException(_takeError(errorOut, result), code: result);
    }
  } finally {
    calloc.free(selfPointer);
    calloc.free(recordPointer);
    calloc.free(errorOut);
  }
}

Future<void> publishSpaceDiscoveryRecordAsync({
  required Uint8List selfNodeId,
  required Uint8List record,
}) =>
    Isolate.run(
      () => publishSpaceDiscoveryRecord(selfNodeId: selfNodeId, record: record),
    );

List<Uint8List> resolveSpaceDiscoveryRecords({
  required Uint8List selfNodeId,
  required SpaceDiscoveryRouteKind routeKind,
  required Uint8List routeBody,
  int timeoutMs = 0,
}) {
  if (selfNodeId.length != 32 || routeBody.length != 32) {
    throw VeilException('node id and discovery route must be 32 bytes');
  }
  final selfPointer = calloc<Uint8>(32);
  final routePointer = calloc<Uint8>(32);
  final output = calloc<Pointer<Uint8>>();
  final outputLength = calloc<IntPtr>();
  final errorOut = calloc<Pointer<Utf8>>();
  try {
    selfPointer.asTypedList(32).setAll(0, selfNodeId);
    routePointer.asTypedList(32).setAll(0, routeBody);
    final result = ffi.veilSpaceDiscoveryResolve(
      selfPointer,
      routeKind.index,
      routePointer,
      timeoutMs,
      output,
      outputLength,
      errorOut,
    );
    if (result != ffi.veilOk) {
      throw VeilException(_takeError(errorOut, result), code: result);
    }
    final bytes = Uint8List.fromList(
      output.value.asTypedList(outputLength.value),
    );
    return decodeSpaceDiscoveryReplicaBuffer(bytes);
  } finally {
    if (output.value != nullptr) {
      ffi.veilFreeBuf(output.value, outputLength.value);
    }
    calloc.free(selfPointer);
    calloc.free(routePointer);
    calloc.free(output);
    calloc.free(outputLength);
    calloc.free(errorOut);
  }
}

Future<List<Uint8List>> resolveSpaceDiscoveryRecordsAsync({
  required Uint8List selfNodeId,
  required SpaceDiscoveryRouteKind routeKind,
  required Uint8List routeBody,
  int timeoutMs = 0,
}) =>
    Isolate.run(
      () => resolveSpaceDiscoveryRecords(
        selfNodeId: selfNodeId,
        routeKind: routeKind,
        routeBody: routeBody,
        timeoutMs: timeoutMs,
      ),
    );

List<Uint8List> decodeSpaceDiscoveryReplicaBuffer(Uint8List bytes) {
  if (bytes.length < 4) {
    throw const FormatException('truncated Space discovery replica buffer');
  }
  final data = ByteData.sublistView(bytes);
  var offset = 0;
  int takeU32() {
    if (offset + 4 > bytes.length) {
      throw const FormatException('truncated Space discovery replica buffer');
    }
    final value = data.getUint32(offset, Endian.little);
    offset += 4;
    return value;
  }

  final count = takeU32();
  if (count > 5) {
    throw const FormatException('too many Space discovery replicas');
  }
  final records = <Uint8List>[];
  for (var index = 0; index < count; index++) {
    final length = takeU32();
    if (length == 0 || length > 17 * 1024 || offset + length > bytes.length) {
      throw const FormatException('invalid Space discovery record length');
    }
    records.add(Uint8List.fromList(bytes.sublist(offset, offset + length)));
    offset += length;
  }
  if (offset != bytes.length) {
    throw const FormatException('trailing Space discovery replica bytes');
  }
  return List<Uint8List>.unmodifiable(records);
}
