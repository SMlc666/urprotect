#include "urp/host_context.h"

__thread int urp_tls_value = 43;

int32_t urp_entry(
    const urp_host_context_v1 *host,
    const urp_launch_args_v1 *args)
{
    if (host == 0 || args == 0 || args->argc != 1U || args->argv == 0) {
        return 19;
    }
    return urp_tls_value;
}
