// report9 V-08.
//
// Three Dart entry points staged y|u|v into native memory sized by the arrays
// they were handed, then declared a `width`x`height` geometry to a C function
// that takes plane POINTERS and no lengths. Native reads `height` rows of
// `width` from Y and `(height+1)/2` rows of `(width+1)/2` from each chroma
// plane and trusts they are there, so a short plane was an out-of-bounds read
// inside the encoder.
//
// `pushAndroid420Frame` in the same file had the check from the start. The
// arithmetic lives in `src/i420.dart` now so a fourth caller cannot write its
// own version, and so it can be tested at all: importing `veil_media.dart`
// opens the native library at import time, which no unit test has.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:veil_media/src/i420.dart';

void main() {
  group('plane sizes', () {
    test('an exact frame fits', () {
      // 640x480: 307200 luma, 320x240 = 76800 per chroma plane.
      expect(i420PlanesFit(307200, 76800, 76800, 640, 480), isTrue);
    });

    test('a plane one byte short does not', () {
      expect(
        i420PlanesFit(307199, 76800, 76800, 640, 480),
        isFalse,
        reason: 'a short LUMA plane is read past its end by the encoder',
      );
      expect(
        i420PlanesFit(307200, 76799, 76800, 640, 480),
        isFalse,
        reason: 'a short U plane is read past its end by the encoder',
      );
      expect(
        i420PlanesFit(307200, 76800, 76799, 640, 480),
        isFalse,
        reason: 'a short V plane is read past its end by the encoder',
      );
    });

    test('padded planes are fine — native reads only what it declared', () {
      expect(i420PlanesFit(400000, 100000, 100000, 640, 480), isTrue);
    });

    test('odd dimensions round chroma up, not down', () {
      // 3x3: chroma is 2x2 = 4, not 1x1. Rounding down would under-state the
      // requirement, which is the direction that lets a short plane through.
      final needs = i420PlaneNeeds(3, 3)!;
      expect(needs.luma, 9);
      expect(needs.chroma, 4);
      expect(i420PlanesFit(9, 3, 4, 3, 3), isFalse);
      expect(i420PlanesFit(9, 4, 4, 3, 3), isTrue);
    });

    test('a geometry that is not a frame is refused outright', () {
      expect(i420PlaneNeeds(0, 480), isNull);
      expect(i420PlaneNeeds(640, 0), isNull);
      expect(i420PlaneNeeds(-1, 480), isNull);
      // Absurd dimensions are refused rather than multiplied: a product that
      // wrapped would understate the requirement and pass everything below.
      expect(i420PlaneNeeds(1 << 30, 1 << 30), isNull);
      expect(i420PlanesFit(0, 0, 0, 0, 0), isFalse);
    });
  });

  // Structural, and deliberately so: what the arithmetic above is worth
  // depends entirely on every staging path calling it. Three of the four did
  // not, for as long as they have existed, and each one is a separate copy of
  // the same eight lines — which is exactly how the fourth one would happen.
  test('every path that stages planes for native checks them first', () {
    final source = File('lib/veil_media.dart').readAsStringSync();

    // Each tightly-packed pusher, and the strided one that always checked.
    const pushers = <String>[
      'bool pushVideoFrame(\n      Uint8List y, Uint8List u, Uint8List v, int width, int height) {',
      'bool pushVideoFrame(\n    Uint8List y,\n    Uint8List u,\n    Uint8List v,\n    int width,\n    int height,\n  ) {',
      'bool pushFrame(Uint8List y, Uint8List u, Uint8List v, int width, int height) {',
    ];

    for (final signature in pushers) {
      final start = source.indexOf(signature);
      expect(
        start,
        isNot(-1),
        reason:
            'a staging path named in this guard is gone from veil_media.dart '
            '— the guard now checks less than it says it does',
      );
      // Bound the body by brace counting from the signature's own brace.
      final open = start + signature.length - 1;
      var depth = 0;
      var end = -1;
      for (var i = open; i < source.length; i++) {
        if (source[i] == '{') depth++;
        if (source[i] == '}') {
          depth--;
          if (depth == 0) {
            end = i;
            break;
          }
        }
      }
      expect(end, isNot(-1), reason: 'could not bound a pusher body');
      final body = source.substring(open, end);

      expect(
        body,
        contains('i420PlanesFit'),
        reason:
            'this path stages planes into native memory and declares a '
            'geometry without checking they supply it — the encoder reads '
            'past the end of a short plane',
      );
      // And the check has to come before the copy, not after it.
      expect(
        body.indexOf('i420PlanesFit'),
        lessThan(body.indexOf('setRange')),
        reason: 'the planes are copied before they are checked',
      );
    }

    // The strided path keeps its own check because its arithmetic is
    // different (strides, a uv pixel stride, rotation). Named here so that
    // deleting it fails something.
    expect(
      source,
      contains('final yNeeded = (height - 1) * yStride + width;'),
      reason: 'the strided pusher lost the bounds check it always had',
    );
  });
}
