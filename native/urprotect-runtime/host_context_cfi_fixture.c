#include "urp/host_context.h"
#include <stdint.h>

__attribute__((noinline, visibility("hidden")))
int32_t urp_transform_target(
    const urp_host_context_v1 *host,
    const urp_launch_args_v1 *args)
{
    /* Keep the unwindable target frame established before callback validation. */
    volatile uint32_t frame_anchor = 0;
    (void)frame_anchor;
    (void)args;
    if (host != 0 && host->emit_diagnostic != 0)
        (void)host->emit_diagnostic(host->userdata, UINT32_C(0xCF10), 0);
    return 42;
}

extern __typeof__(urp_transform_target) urp_entry
    __attribute__((alias("urp_transform_target"), visibility("default")));
