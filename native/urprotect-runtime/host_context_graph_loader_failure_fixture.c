#include "urp/host_context.h"

#include <stdint.h>

extern void urp_missing_graph_loader_symbol(void);

int32_t urp_entry(const urp_host_context_v1 *host, const urp_launch_args_v1 *args)
{
    (void)host;
    (void)args;
    urp_missing_graph_loader_symbol();
    return 41;
}
