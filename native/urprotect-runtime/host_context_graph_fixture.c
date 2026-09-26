#include "urp/host_context.h"
#include "host_context_graph_fixture_contract.h"

#include <stdint.h>

static volatile int graph_constructor_ran;

static long graph_syscall4(
    long number,
    long argument0,
    long argument1,
    long argument2,
    long argument3)
{
    register long x0 __asm__("x0") = argument0;
    register long x1 __asm__("x1") = argument1;
    register long x2 __asm__("x2") = argument2;
    register long x3 __asm__("x3") = argument3;
    register long x8 __asm__("x8") = number;
    __asm__ volatile(
        "svc 0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x8)
        : "memory");
    return x0;
}

__attribute__((constructor)) static void graph_constructor(void)
{
    graph_constructor_ran = 1;
}

__attribute__((destructor)) static void graph_destructor(void)
{
    static const char released[] = "released\n";
    long fd = graph_syscall4(56L, -100L,
        (long)URP_GRAPH_LIFECYCLE_MARKER_PATH, 1L | 64L | 512L, 0600L);
    if (fd >= 0L) {
        (void)graph_syscall4(64L, fd, (long)released, (long)(sizeof(released) - 1U), 0L);
        (void)graph_syscall4(57L, fd, 0L, 0L, 0L);
    }
}

int32_t urp_entry(const urp_host_context_v1 *host, const urp_launch_args_v1 *args)
{
    return host != 0 && args != 0 && graph_constructor_ran != 0 ? 37 : 39;
}
