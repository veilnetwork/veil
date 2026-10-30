#include <stdint.h>
#include <stdlib.h>

/* Stand-only ABI: no audio device or network is opened. */
static int refuse_capture = 1;
static int last_muted = -1;

void *veil_media_engine_create(uint64_t channel, const uint8_t *local,
                               const uint8_t *peer) {
  (void)channel; (void)local; (void)peer;
  return malloc(1);
}
void veil_media_engine_destroy(void *engine) { free(engine); }
int veil_media_engine_set_mic_muted(void *engine, int muted) {
  if (!engine) return -1;
  last_muted = muted;
  return !muted && refuse_capture ? -7 : 0;
}
void stand_allow_capture(void) { refuse_capture = 0; }
int stand_last_muted(void) { return last_muted; }
