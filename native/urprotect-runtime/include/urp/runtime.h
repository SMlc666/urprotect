#ifndef URP_RUNTIME_H
#define URP_RUNTIME_H

#include "urp/host_context.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define URP_RUNTIME_MAX_SOURCE_SIZE (UINT64_C(256) * UINT64_C(1024) * UINT64_C(1024))
#define URP_RUNTIME_MAX_ENTRY_NAME 4096U

/* Execute one verified v1 payload frame through the supplied host contract. */
urp_status urp_runtime_execute_frame(
    const urp_host_context_v1 *host,
    const uint8_t *frame,
    size_t frame_size,
    const urp_launch_args_v1 *args);

#ifdef __cplusplus
}
#endif

#endif
