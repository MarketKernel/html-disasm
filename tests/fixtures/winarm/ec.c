/* ARM64EC code: Arm code that x64 code in the same process can call. */
int counter;
__declspec(dllexport) int add(int a, int b) { return a + b + counter; }
__declspec(dllexport) int twice(int (*f)(int, int), int x) { return f(x, x) * 2; }
