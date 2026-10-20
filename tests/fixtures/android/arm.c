// Built as A32 code (-marm) on armeabi-v7a, so the library holds both instruction sets.
#include <stddef.h>
#include <stdint.h>

__attribute__((noinline)) long scale(long value, int by) {
  long result = value;
  for (int i = 0; i < by; i++) result = result * 3 + (result >> 2);
  return result;
}

__attribute__((noinline)) uint32_t checksum(const uint8_t *bytes, size_t n) {
  uint32_t a = 1, b = 0;
  for (size_t i = 0; i < n; i++) {
    a = (a + bytes[i]) % 65521;
    b = (b + a) % 65521;
  }
  return (b << 16) | a;
}
