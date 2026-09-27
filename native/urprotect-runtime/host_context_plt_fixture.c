#include "urp/host_context.h"

#include <stdint.h>

extern int urp_weak_probe(void) __attribute__((weak));
__asm__(".weak urp_weak_probe\n.type urp_weak_probe, %function");

int32_t urp_entry(
    const urp_host_context_v1 *host,
    const urp_launch_args_v1 *args)
{
    if (host == 0 || args == 0 || args->argc != 1U || args->argv == 0) {
        return 19;
    }
    if (urp_weak_probe == 0) {
        return 53;
    }
    return urp_weak_probe();
}
