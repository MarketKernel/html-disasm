/* Plain arm64 code: what an Arm process runs from an ARM64X library. */
__declspec(dllexport) int add(int a, int b) { return a - b; }
__declspec(dllexport) int native_only(int x) { return x * 3; }
