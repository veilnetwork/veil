// Test-only bind response: the originating Dart event loop must release it.
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static int entered, released, completed, closed, mode, freed, app_closed;
static int observed_variant, arguments_valid;
static uint32_t endpoint;

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
  closed++;
  pthread_mutex_unlock(&mutex);
}
void veil_free_string(char *value) {
  free(value);
  pthread_mutex_lock(&mutex);
  freed++;
  pthread_mutex_unlock(&mutex);
}
void bind_test_mode(int value) {
  pthread_mutex_lock(&mutex);
  mode = value;
  pthread_mutex_unlock(&mutex);
}
static int read_locked(int *field) {
  pthread_mutex_lock(&mutex);
  int result = *field;
  pthread_mutex_unlock(&mutex);
  return result;
}
int bind_test_entered(void) { return read_locked(&entered); }
int bind_test_completed(void) { return read_locked(&completed); }
int bind_test_freed(void) { return read_locked(&freed); }
int bind_test_closed(void) { return read_locked(&closed); }
int bind_test_app_closed(void) { return read_locked(&app_closed); }
int bind_test_variant(void) { return read_locked(&observed_variant); }
int bind_test_arguments_valid(void) { return read_locked(&arguments_valid); }
void bind_test_release(void) {
  pthread_mutex_lock(&mutex);
  released = 1;
  pthread_cond_broadcast(&condition);
  pthread_mutex_unlock(&mutex);
}
static void *bind_endpoint(int variant, void *handle,
    const uint8_t *ns, intptr_t ns_length,
    const uint8_t *name, intptr_t name_length,
    uint32_t endpoint_id, char **error) {
  const char *expected_ns = "qa.namespace.λ", *expected_name = "name.тест";
  pthread_mutex_lock(&mutex);
  entered++;
  observed_variant = variant;
  endpoint = endpoint_id;
  arguments_valid = handle == (void *)(uintptr_t)1 &&
      ns_length == (intptr_t)strlen(expected_ns) &&
      name_length == (intptr_t)strlen(expected_name) &&
      memcmp(ns, expected_ns, (size_t)ns_length) == 0 &&
      memcmp(name, expected_name, (size_t)name_length) == 0 &&
      endpoint_id == 0x12345678;
  struct timespec deadline;
  clock_gettime(CLOCK_REALTIME, &deadline);
  deadline.tv_sec += 2; // Hang guard only; success requires the Dart release.
  while (!released) {
    if (pthread_cond_timedwait(&condition, &mutex, &deadline) != 0) {
      *error = strdup("calling event loop did not release bind");
      pthread_mutex_unlock(&mutex);
      return NULL;
    }
  }
  completed++;
  // An admitted native operation can retain its bundle and succeed even if
  // the caller closes the parent client before the response (mode 3).
  int failed = mode == 1 || (closed && mode != 3) || !arguments_valid;
  if (failed) *error = strdup("controlled bind refusal");
  pthread_mutex_unlock(&mutex);
  return failed ? NULL : (void *)(uintptr_t)32;
}
#define BIND_ENTRY(symbol, variant) \
void *symbol(void *handle, const uint8_t *ns, intptr_t ns_length, \
    const uint8_t *name, intptr_t name_length, uint32_t endpoint_id, char **error) { \
  return bind_endpoint(variant, handle, ns, ns_length, name, name_length, \
      endpoint_id, error); \
}
BIND_ENTRY(veil_bind, 0)
BIND_ENTRY(veil_bind_named, 1)
BIND_ENTRY(veil_bind_device_scoped, 2)
int veil_app_get_app_id(void *app, uint8_t *out) {
  (void)app;
  for (int i = 0; i < 32; i++) out[i] = (uint8_t)(i + observed_variant);
  return 0;
}
uint32_t veil_app_get_endpoint_id(void *app) { (void)app; return endpoint; }
void veil_app_close(void *app) {
  (void)app;
  pthread_mutex_lock(&mutex);
  app_closed++;
  pthread_mutex_unlock(&mutex);
}
