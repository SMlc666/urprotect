#include "host_context_graph_fixture_contract.h"

__attribute__((constructor)) static void fake_loader_constructor(void)
{
    register long x0 __asm__("x0") = -100L;
    register long x1 __asm__("x1") = (long)URP_FAKE_LOADER_MARKER_PATH;
    register long x2 __asm__("x2") = 1L | 64L | 512L;
    register long x3 __asm__("x3") = 0600L;
    register long x8 __asm__("x8") = 56L;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x8) : "memory");
    long fd = x0;
    if (fd >= 0) {
        static const char loaded[] = "fake-loader-loaded\n";
        register long write_x0 __asm__("x0") = fd;
        register long write_x1 __asm__("x1") = (long)loaded;
        register long write_x2 __asm__("x2") = (long)(sizeof(loaded) - 1U);
        register long write_x8 __asm__("x8") = 64L;
        __asm__ volatile("svc 0" : "+r"(write_x0) : "r"(write_x1), "r"(write_x2), "r"(write_x8) : "memory");
        register long close_x0 __asm__("x0") = fd;
        register long close_x8 __asm__("x8") = 57L;
        __asm__ volatile("svc 0" : "+r"(close_x0) : "r"(close_x8) : "memory");
    }
}
