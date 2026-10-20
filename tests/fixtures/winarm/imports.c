/* Calls through the import address table, as MSVC compiles a function declared dllimport. */
__declspec(dllimport) int ext_call(int);
__declspec(dllimport) void ext_log(const char *);
__declspec(dllexport) int use_imports(int x) {
  ext_log("calling");
  return ext_call(x) + ext_call(x + 1);
}
