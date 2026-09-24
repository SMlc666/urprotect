#include "urp/host_context.h"

#include <stdint.h>

struct gnu_property_note {
    uint32_t namesz;
    uint32_t descsz;
    uint32_t type;
    char name[4];
    uint32_t property_type;
    uint32_t property_size;
    uint32_t property_data;
    uint32_t padding;
};

__attribute__((section(".note.gnu.property"), used, aligned(8)))
static const struct gnu_property_note urp_property_note = {
    4U,
    16U,
    5U,
    {'G', 'N', 'U', '\0'},
    UINT32_C(0xC0000000),
    4U,
    1U,
    0U,
};

int32_t urp_entry(
    const urp_host_context_v1 *host,
    const urp_launch_args_v1 *args)
{
    (void)urp_property_note;
    if (host == 0 || args == 0 || args->argc != 1U || args->argv == 0) {
        return 19;
    }
    return 47;
}
