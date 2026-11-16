/* SPDX-License-Identifier: MIT */
#pragma once
#if !defined(VEIL_MEDIA_MF_CAMERA_TEST)
#error This compile-only header is restricted to the MF metadata fixture.
#endif

// Compile-only stand-ins for metadata and stale-sample admission. Conversion
// attempts are counted and refused, never simulated as successful frames.
namespace libyuv {
inline int metadata_conversion_calls = 0;
inline int NV12ToI420(...) { ++metadata_conversion_calls; return -1; }
inline int YUY2ToI420(...) { ++metadata_conversion_calls; return -1; }
inline int ARGBToI420(...) { ++metadata_conversion_calls; return -1; }
}
