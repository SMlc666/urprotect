#include "urp/host_context.h"

extern int32_t urp_switch_target(int32_t value);

int32_t urp_entry(
    const urp_host_context_v1 *host,
    const urp_launch_args_v1 *args)
{
    (void)host;
    (void)args;
    return urp_switch_target(3);
}
