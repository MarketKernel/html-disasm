// The sample program the tests open: a little of everything a disassembler meets —
// strings, a loop, a switch, calls into libSystem, floating point and an atomic.
// Rebuild with: clang -O1 -arch arm64 -o hello hello.c   (the tests pin what it contains)
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static _Atomic long counter;

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

int main(int argc, char **argv) {
  int values[8] = {42, -7, 19, 3, 88, 0, -15, 61};
  atomic_fetch_add_explicit(&counter, argc, memory_order_release);
  printf("Hello, world! sum=%ld avg=%.2f kind=%s\n", sum(values, 8), average(values, 8), kind(argc));
  if (argc > 1 && strcmp(argv[1], "--help") == 0) puts("usage: hello [--help]");
  char *copy = malloc(32);
  if (!copy) return 1;
  strncpy(copy, argv[0], 31);
  copy[31] = 0;
  free(copy);
  return (int)atomic_load(&counter) > 100;
}
