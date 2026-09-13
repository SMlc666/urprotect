#include "urp/host_context.h"

static int host_context_result = 23;
static int *volatile host_context_result_pointer = &host_context_result;

int32_t urp_entry(
    const urp_host_context_v1 *host,
    const urp_launch_args_v1 *args)
{
    if (host == 0 || args == 0 || args->argc != 1U || args->argv == 0) {
        return 19;
    }
    return *host_context_result_pointer;
}
