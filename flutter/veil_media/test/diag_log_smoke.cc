/* SPDX-License-Identifier: MIT */

#include "../src/veil_diag_log.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>

int main() {
  const char* output_path = "/tmp/veil_media_diag_smoke.log";
  std::remove(output_path);
  unsetenv("VEIL_MEDIA_DIAG_PATH");

  if (veil_media::diag::enabled()) return 1;
  veil_media::diag::log("disabled line");
  if (std::ifstream(output_path).good()) return 2;

  if (setenv("VEIL_MEDIA_DIAG_PATH", output_path, 1) != 0) return 3;
  if (!veil_media::diag::enabled()) return 4;
  veil_media::diag::log("enabled line %d", 7);

  std::ifstream input(output_path);
  std::string line;
  std::getline(input, line);
  std::remove(output_path);
  return line == "enabled line 7" ? 0 : 5;
}
