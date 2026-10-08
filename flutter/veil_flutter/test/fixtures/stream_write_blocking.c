// Test-only FFI boundary: a native write must wait for the Dart event loop.
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static int entered, released, order;
static int progress_mode, permits, total, finished_total, fail_after;
static uint32_t checksum;
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
void stream_test_progress_mode(void) {
  pthread_mutex_lock(&mutex);
  progress_mode = 1;
  entered = released = order = permits = total = finished_total = fail_after = 0;
  checksum = 0;
  pthread_mutex_unlock(&mutex);
}
void stream_test_permit(void) {
  pthread_mutex_lock(&mutex);
  permits++;
  pthread_cond_broadcast(&condition);
  pthread_mutex_unlock(&mutex);
}
void stream_test_fail_after(int value) {
  pthread_mutex_lock(&mutex);
  fail_after = value;
  pthread_mutex_unlock(&mutex);
}
int stream_test_total(void) {
  pthread_mutex_lock(&mutex);
  int value = total;
  pthread_mutex_unlock(&mutex);
  return value;
}
uint32_t stream_test_checksum(void) {
  pthread_mutex_lock(&mutex);
  uint32_t value = checksum;
  pthread_mutex_unlock(&mutex);
  return value;
}
int stream_test_finished_total(void) {
  pthread_mutex_lock(&mutex);
  int value = finished_total;
  pthread_mutex_unlock(&mutex);
  return value;
}
int veil_stream_write(void *handle, const uint8_t *bytes, size_t length, char **error) {
  (void)handle;
  pthread_mutex_lock(&mutex);
  entered++;
  if (progress_mode) {
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 2;
    while (!permits && !released) {
      if (pthread_cond_timedwait(&condition, &mutex, &deadline) != 0) {
        *error = strdup("Dart event loop did not permit progress write");
        pthread_mutex_unlock(&mutex);
        return -1;
      }
    }
    if (permits) permits--;
    if (fail_after && total >= fail_after) {
      *error = strdup("test peer reset after accepted prefix");
      pthread_mutex_unlock(&mutex);
      return -1;
    }
    for (size_t i = 0; i < length; i++) checksum = checksum * 31 + bytes[i];
    total += (int)length;
    pthread_mutex_unlock(&mutex);
    return 0;
  }
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
int veil_anon_stream_write(void *handle, const uint8_t *bytes, size_t length, char **error) {
  return veil_stream_write(handle, bytes, length, error);
}
int veil_anon_stream_finish(void *handle, char **error) {
  (void)handle; (void)error;
  pthread_mutex_lock(&mutex);
  finished_total = total;
  pthread_mutex_unlock(&mutex);
  return 0;
}
void veil_anon_stream_close(void *handle) { (void)handle; }
void veil_anon_stream_abort(void *handle) { (void)handle; stream_test_release(); }
