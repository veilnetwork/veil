/* SPDX-License-Identifier: MIT */
#pragma once
#if !defined(VEIL_MEDIA_MF_CAMERA_TEST)
#error This compile-only header is restricted to the MF metadata fixture.
#endif
#include "convert.h"
namespace libyuv {
enum FilterMode { kFilterBilinear = 2 };
inline int I420Scale(...) { ++metadata_conversion_calls; return -1; }
}
