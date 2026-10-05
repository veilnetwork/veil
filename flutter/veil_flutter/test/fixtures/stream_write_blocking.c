// Test-only FFI boundary: a native write must wait for the Dart event loop.
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static int entered, released, order;
const char *veil_abi_contract_hash(void) { return XVEIL_TEST_ABI_HASH; }
void veil_stream_close(void *handle) { (void)handle; }
void veil_stream_close_finalizer(void *handle) { (void)handle; }
void veil_free_string(char *value) { free(value); }
int stream_test_entered(void) {
  pthread_mutex_lock(&mutex);
  int result = entered;
  pthread_mutex_unlock(&mutex);
  return result;
}
int stream_test_order(void) {
  pthread_mutex_lock(&mutex);
  int result = order;
  pthread_mutex_unlock(&mutex);
  return result;
}
void stream_test_release(void) {
  pthread_mutex_lock(&mutex);
  released = 1;
  pthread_cond_broadcast(&condition);
  pthread_mutex_unlock(&mutex);
}
int veil_stream_write(void *handle, const uint8_t *bytes, size_t length, char **error) {
  (void)handle;
  pthread_mutex_lock(&mutex);
  entered++;
  order = order * 10 + (length ? bytes[0] : 0);
  if (length && bytes[0] == 1) {
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 2;
    while (!released) {
      if (pthread_cond_timedwait(&condition, &mutex, &deadline) != 0) {
        *error = strdup("Dart event loop did not release blocked write");
        pthread_mutex_unlock(&mutex);
        return -1;
      }
    }
  }
  pthread_mutex_unlock(&mutex);
  return 0;
}
