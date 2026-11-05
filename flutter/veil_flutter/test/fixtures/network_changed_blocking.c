// Test-only IPC stand-in: completion requires the calling Dart event loop.
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static int entered, released, completed, closed, mode, freed;
static int observed_kind, observed_mtu;

const char *veil_abi_contract_hash(void) { return XVEIL_TEST_ABI_HASH; }
void *veil_connect(const uint8_t *path, intptr_t length, char **error) {
  (void)path; (void)length; (void)error;
  return (void *)(uintptr_t)1;
}
int veil_set_event_handler(void *handle, void *callback, void *user, char **error) {
  (void)handle; (void)callback; (void)user; (void)error;
  return 0;
}
void veil_close(void *handle) {
  (void)handle;
  pthread_mutex_lock(&mutex);
  closed = 1;
  pthread_mutex_unlock(&mutex);
}
void veil_free_string(char *value) {
  free(value);
  pthread_mutex_lock(&mutex);
  freed++;
  pthread_mutex_unlock(&mutex);
}
void network_test_mode(int value) {
  pthread_mutex_lock(&mutex);
  mode = value;
  pthread_mutex_unlock(&mutex);
}
int network_test_entered(void) {
  pthread_mutex_lock(&mutex);
  int result = entered;
  pthread_mutex_unlock(&mutex);
  return result;
}
int network_test_completed(void) {
  pthread_mutex_lock(&mutex);
  int result = completed;
  pthread_mutex_unlock(&mutex);
  return result;
}
static int read_locked(int *field) {
  pthread_mutex_lock(&mutex);
  int result = *field;
  pthread_mutex_unlock(&mutex);
  return result;
}
int network_test_freed(void) { return read_locked(&freed); }
int network_test_kind(void) { return read_locked(&observed_kind); }
int network_test_mtu(void) { return read_locked(&observed_mtu); }
void network_test_release(void) {
  pthread_mutex_lock(&mutex);
  released = 1;
  pthread_cond_broadcast(&condition);
  pthread_mutex_unlock(&mutex);
}
int veil_notify_network_changed(void *handle, int kind, uint16_t mtu, char **error) {
  (void)handle;
  pthread_mutex_lock(&mutex);
  entered++;
  observed_kind = kind;
  observed_mtu = mtu;
  struct timespec deadline;
  clock_gettime(CLOCK_REALTIME, &deadline);
  deadline.tv_sec += 2; // Failure guard only; successful completion needs release.
  while (!released) {
    if (pthread_cond_timedwait(&condition, &mutex, &deadline) != 0) {
      *error = strdup("calling event loop did not release network dispatch");
      pthread_mutex_unlock(&mutex);
      return -1;
    }
  }
  completed++;
  int failed = mode || closed;
  if (failed) *error = strdup("controlled network dispatch refusal");
  pthread_mutex_unlock(&mutex);
  return failed ? -1 : 0;
}
