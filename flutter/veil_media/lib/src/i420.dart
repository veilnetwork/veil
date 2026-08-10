/// Plane-size arithmetic for tightly-packed I420, kept apart from the FFI
/// bindings on purpose: it is the one piece of this contract that can be
/// checked without a native library present.
library;

/// Bytes each plane of a tightly-packed I420 frame of [width]x[height] must
/// supply, or null when the geometry is not a frame at all.
///
/// The C ABI takes plane POINTERS and no lengths, so the native side cannot
/// make this check: it reads `height` rows of `width` bytes from Y and
/// `(height + 1) ~/ 2` rows of `(width + 1) ~/ 2` from each chroma plane, and
/// trusts they are there. Every Dart caller that stages planes into native
/// memory and then declares a geometry is therefore the last place the two can
/// be reconciled — a plane shorter than what it declared is an out-of-bounds
/// read inside the encoder (report9 V-08).
///
/// `pushAndroid420Frame` had this check from the start, with strides. The
/// tightly-packed paths did not, which is why the arithmetic lives here now
/// instead of being written out a fourth time.
({int luma, int chroma})? i420PlaneNeeds(int width, int height) {
  if (width <= 0 || height <= 0) return null;
  // Guard the multiplication rather than trusting the caller's ints: these
  // arrive from a camera callback, and a bogus geometry that overflows into a
  // small product would pass every check below it.
  if (width > _maxDimension || height > _maxDimension) return null;
  final chromaWidth = (width + 1) ~/ 2;
  final chromaHeight = (height + 1) ~/ 2;
  return (luma: width * height, chroma: chromaWidth * chromaHeight);
}

/// Whether [y], [u] and [v] lengths supply a [width]x[height] I420 frame.
///
/// Longer is fine — a padded plane is still readable at every offset native
/// will touch. Shorter is not.
bool i420PlanesFit(
  int yLength,
  int uLength,
  int vLength,
  int width,
  int height,
) {
  final needs = i420PlaneNeeds(width, height);
  if (needs == null) return false;
  return yLength >= needs.luma &&
      uLength >= needs.chroma &&
      vLength >= needs.chroma;
}

/// 16384 is past any camera or screen this ships against, and squares to a
/// number far below the point where Dart's ints stop being exact.
const int _maxDimension = 16384;
