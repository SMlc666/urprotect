#include "urp/host_context.h"

#include <stdint.h>

extern int urp_weak_value[] __attribute__((weak));

int32_t urp_entry(
    const urp_host_context_v1 *host,
    const urp_launch_args_v1 *args)
{
    if (host == 0 || args == 0 || args->argc != 1U || args->argv == 0) {
        return 19;
    }
    uintptr_t weak_address = (uintptr_t)&urp_weak_value;
    return weak_address == 0U ? 29 : 31;
}
