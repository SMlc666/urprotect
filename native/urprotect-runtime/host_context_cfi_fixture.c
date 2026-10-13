#include "urp/host_context.h"
#include <stdint.h>

__attribute__((noinline, visibility("hidden")))
int32_t urp_transform_target(
    const urp_host_context_v1 *host,
    const urp_launch_args_v1 *args)
{
    (void)args;
    if (host != 0 && host->emit_diagnostic != 0)
        (void)host->emit_diagnostic(host->userdata, UINT32_C(0xCF10), 0);
    return 42;
}

int32_t urp_entry(
    const urp_host_context_v1 *host,
    const urp_launch_args_v1 *args)
{
    return urp_transform_target(host, args);
}
