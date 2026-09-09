/* SPDX-License-Identifier: MIT
 *
 * veil_vp8_header.h — the geometry a VP8 keyframe declares, read before the
 * frame is handed to a decoder.
 *
 * WHY THIS EXISTS, and why it is not the sink guard.
 *
 * `VnoteDecodeSink::Decoded` bounds the RGBA buffer it fills, and that is a
 * real bound on OUR allocation. It runs too late to be the only one: libvpx
 * reads the keyframe's own 14-bit dimensions and allocates four YV12 reference
 * buffers from them BEFORE any callback of ours is reached, and a malformed
 * frame may never reach one at all. At the codec's maximum of 16383 square
 * that is about 1.5 GiB of allocation requests from a clip somebody sent —
 * arithmetic on the sizes libvpx computes, not a measured RSS — and these
 * builds are `-fno-exceptions`, where a refused allocation aborts (report24
 * MEDIA-3).
 *
 * So the geometry is read from the frame first, and a frame that declares more
 * than this product allows is refused before the decoder sees it. The sink
 * guard stays as the second bound: the decoder can also report a size that
 * disagrees with its own keyframe.
 *
 * The layout is RFC 6386 §9.1: a three-byte frame tag whose lowest bit is 0
 * for a keyframe, the three-byte start code 9d 01 2a, then width and height as
 * little-endian 16-bit values carrying 14 bits of size and 2 bits of scale.
 * Delta frames cannot change the dimensions, so a keyframe is the only place
 * this question is asked.
 */

#ifndef VEIL_VP8_HEADER_H_
#define VEIL_VP8_HEADER_H_

#include <cstddef>
#include <cstdint>

struct VeilVp8Size {
  /// False when these bytes are not a VP8 keyframe header this can read: too
  /// short, a delta frame, or a missing start code. The caller refuses such a
  /// frame rather than guessing — a frame the index calls a keyframe and the
  /// bytes do not is one no decoder can start a reference chain from anyway.
  bool ok;
  int w;
  int h;
};

/// Read a VP8 keyframe's declared size. Pure arithmetic on the first ten
/// bytes; no allocation, no decoding.
constexpr VeilVp8Size veil_vp8_keyframe_size(const uint8_t* data, size_t len) {
  if (data == nullptr || len < 10) return VeilVp8Size{false, 0, 0};
  // Frame tag, bit 0: 0 = keyframe, 1 = interframe.
  if ((data[0] & 0x01) != 0) return VeilVp8Size{false, 0, 0};
  if (data[3] != 0x9d || data[4] != 0x01 || data[5] != 0x2a) {
    return VeilVp8Size{false, 0, 0};
  }
  const int w = (int)((uint16_t)(data[6] | ((uint16_t)data[7] << 8)) & 0x3fff);
  const int h = (int)((uint16_t)(data[8] | ((uint16_t)data[9] << 8)) & 0x3fff);
  return VeilVp8Size{true, w, h};
}

// ── build-time checks ────────────────────────────────────────────────────────
//
// The parser is byte arithmetic, so it can be exercised where it is defined:
// these run on every compilation of every target that includes this header,
// which is the only test bench this plugin's native half has.
namespace veil_vp8_header_selftest {

/// 640 x 480, scale bits clear: 640 = 0x0280, 480 = 0x01e0.
constexpr uint8_t kKeyframe640x480[10] = {0x00, 0x00, 0x00, 0x9d, 0x01,
                                          0x2a, 0x80, 0x02, 0xe0, 0x01};
/// The codec's ceiling, 16383 square, with both scale bits SET — the shape the
/// size gate exists to refuse, and proof the scale bits are not read as size.
constexpr uint8_t kKeyframeMax[10] = {0x00, 0x00, 0x00, 0x9d, 0x01,
                                      0x2a, 0xff, 0xff, 0xff, 0xff};
/// Same bytes, frame tag marked as an interframe.
constexpr uint8_t kInterframe[10] = {0x01, 0x00, 0x00, 0x9d, 0x01,
                                     0x2a, 0x80, 0x02, 0xe0, 0x01};
/// A keyframe tag with the start code corrupted.
constexpr uint8_t kBadStartCode[10] = {0x00, 0x00, 0x00, 0x9d, 0x01,
                                       0x2b, 0x80, 0x02, 0xe0, 0x01};

static_assert(veil_vp8_keyframe_size(kKeyframe640x480, 10).ok);
static_assert(veil_vp8_keyframe_size(kKeyframe640x480, 10).w == 640);
static_assert(veil_vp8_keyframe_size(kKeyframe640x480, 10).h == 480);
static_assert(veil_vp8_keyframe_size(kKeyframeMax, 10).w == 16383,
              "the two high bits are a SCALE, not part of the size");
static_assert(veil_vp8_keyframe_size(kKeyframeMax, 10).h == 16383);
static_assert(!veil_vp8_keyframe_size(kInterframe, 10).ok,
              "an interframe declares no size and must not be read as one");
static_assert(!veil_vp8_keyframe_size(kBadStartCode, 10).ok);
static_assert(!veil_vp8_keyframe_size(kKeyframe640x480, 9).ok,
              "nine bytes cannot hold a keyframe header");
static_assert(!veil_vp8_keyframe_size(nullptr, 10).ok);

}  // namespace veil_vp8_header_selftest

#endif  // VEIL_VP8_HEADER_H_
