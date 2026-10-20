/* x64 code beside the ARM64EC code. */
__declspec(dllexport) long long xmul(long long a, long long b) { return a * b + 7; }
__declspec(dllexport) int xcount(const volatile char *s) { int n = 0; while (s[n]) n++; return n; }
