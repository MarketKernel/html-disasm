// The functions hello.c calls, for the i386 stand-in of libSystem the program links with.
int printf(const char *format, ...) { return 0; }
int puts(const char *s) { return 0; }
int strcmp(const char *a, const char *b) { return 0; }
long labs(long a) { return a; }
void exit(int code) { for (;;) {} }
void __stack_chk_fail(void) {}
long __stack_chk_guard[8];
void stub_binder(void) __asm__("dyld_stub_binder");
void stub_binder(void) {}
