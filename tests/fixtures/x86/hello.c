// The sample x86 program the tests open, built by build.sh for Linux (x86-64 and i386, glibc),
// Android (x86_64 and x86 libraries) and macOS (x86-64, in a universal file with arm64), and by
// ../linux/build.sh for Linux on arm64 and armhf:
// strings, a loop, a switch with a jump table, calls into libc, SSE, an atomic.
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__x86_64__) || defined(__i386__)
#include <xmmintrin.h>
#endif

static _Atomic long counter;

__attribute__((noinline)) long sum(const int *values, long n) {
  long total = 0;
  for (long i = 0; i < n; i++) total += values[i];
  return total;
}

// Dense cases, each doing something different: compilers make a jump table of it.
__attribute__((noinline)) long step(int op, long a, long b) {
  switch (op) {
    case 0: return a + b;
    case 1: return a - b;
    case 2: return a * b;
    case 3: return b ? a / b : 0;
    case 4: return a << (b & 31);
    case 5: return a >> (b & 31);
    case 6: return a ^ b;
    case 7: return labs(a - b);
    default: return -1;
  }
}

__attribute__((noinline)) float scale4(float *v, float by) {
#if defined(__x86_64__) || defined(__i386__)
  __m128 x = _mm_mul_ps(_mm_loadu_ps(v), _mm_set1_ps(by));
  _mm_storeu_ps(v, x);
#else  // the arm64 slice of the macOS build
  for (int i = 0; i < 4; i++) v[i] *= by;
#endif
  return v[0] + v[3];
}

int main(int argc, char **argv) {
  int values[8] = {42, -7, 19, 3, 88, 0, -15, 61};
  float v[4] = {1, 2, 3, 4};
  atomic_fetch_add_explicit(&counter, argc, memory_order_release);
  printf("Hello, x86! sum=%ld step=%ld scaled=%.1f\n", sum(values, 8), step(argc, 40, 2), (double)scale4(v, 2.5f));
  if (argc > 1 && strcmp(argv[1], "--help") == 0) puts("usage: hello [--help]");
  return (int)atomic_load(&counter) > 100;
}
