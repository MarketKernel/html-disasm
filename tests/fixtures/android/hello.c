// The sample Android library the tests open, built for armeabi-v7a (Thumb-2, with arm.c in
// A32) and arm64-v8a: JNI entry points, strings, a loop, a switch, calls into libc and liblog,
// floating point, NEON, 64-bit division and an atomic. Rebuild with build.sh (needs the NDK).
#include <android/log.h>
#include <arm_neon.h>
#include <jni.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static _Atomic long counter;

long scale(long value, int by);  // arm.c: A32 code on armeabi-v7a
uint32_t checksum(const uint8_t *bytes, size_t n);

__attribute__((noinline)) long sum(const int *values, long n) {
  long total = 0;
  for (long i = 0; i < n; i++) total += values[i];
  return total;
}

__attribute__((noinline)) const char *kind(int c) {
  switch (c) {
    case 0: return "zero";
    case 1: return "one";
    case 2: return "two";
    case 3: return "three";
    case 4: return "four";
    default: return "many";
  }
}

__attribute__((noinline)) double average(const int *values, long n) {
  return n ? (double)sum(values, n) / (double)n : 0.0;
}

__attribute__((noinline)) void add_vectors(float *out, const float *a, const float *b, int n) {
  int i = 0;
  for (; i + 4 <= n; i += 4) vst1q_f32(out + i, vmlaq_n_f32(vld1q_f32(a + i), vld1q_f32(b + i), 0.5f));
  for (; i < n; i++) out[i] = a[i] + b[i] * 0.5f;
}

__attribute__((noinline)) int64_t ratio(int64_t a, int64_t b) {
  return b ? a / b + a % b : 0;
}

typedef int (*compare_fn)(const char *, const char *);

__attribute__((noinline)) int matches(compare_fn compare, const char *a, const char *b) {
  return compare(a, b) == 0;
}

JNIEXPORT jstring JNICALL Java_com_example_hello_Native_greet(JNIEnv *env, jclass cls, jint count) {
  (void)cls;
  int values[8] = {42, -7, 19, 3, 88, 0, -15, 61};
  atomic_fetch_add_explicit(&counter, count, memory_order_release);
  __android_log_print(ANDROID_LOG_INFO, "hello", "sum=%ld avg=%.2f kind=%s scaled=%ld", sum(values, 8), average(values, 8), kind(count), scale(count, 3));
  char *copy = malloc(64);
  if (!copy) return NULL;
  strncpy(copy, matches(strcmp, kind(count), "many") ? "Hello, many!" : "Hello, world!", 63);
  copy[63] = 0;
  jstring result = (*env)->NewStringUTF(env, copy);
  free(copy);
  return result;
}

JNIEXPORT jint JNICALL Java_com_example_hello_Native_checksum(JNIEnv *env, jclass cls, jbyteArray data) {
  (void)cls;
  jsize n = (*env)->GetArrayLength(env, data);
  jbyte *bytes = (*env)->GetByteArrayElements(env, data, NULL);
  uint32_t sum = checksum((const uint8_t *)bytes, (size_t)n);
  (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
  return (jint)(sum + (uint32_t)ratio(n, 7) + (uint32_t)atomic_load(&counter));
}

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
  (void)vm;
  (void)reserved;
  __android_log_write(ANDROID_LOG_DEBUG, "hello", "loaded");
  return JNI_VERSION_1_6;
}
