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
#define URP_RUNTIME_FRAME_VERSION_V1 UINT16_C(1)
#define URP_RUNTIME_FRAME_VERSION_V2 UINT16_C(2)
#define URP_RUNTIME_FRAME_COMMON_HEADER_SIZE UINT16_C(112)
#define URP_RUNTIME_FRAME_V1_HEADER_SIZE URP_RUNTIME_FRAME_COMMON_HEADER_SIZE
#define URP_RUNTIME_FRAME_V2_HEADER_SIZE UINT16_C(136)
#define URP_RUNTIME_FRAME_V2_HOST_ABI_OFFSET UINT16_C(112)
#define URP_RUNTIME_FRAME_V2_RESERVED_BEFORE_CAPABILITIES_OFFSET UINT16_C(116)
#define URP_RUNTIME_FRAME_V2_REQUIRED_CAPABILITIES_OFFSET UINT16_C(120)
#define URP_RUNTIME_FRAME_V2_ENTRY_NAME_SIZE_OFFSET UINT16_C(128)
#define URP_RUNTIME_FRAME_V2_RESERVED_AFTER_ENTRY_NAME_SIZE_OFFSET UINT16_C(132)

/* Execute one verified v1 or v2 payload frame through the supplied host contract. */
urp_status urp_runtime_execute_frame(
    const urp_host_context_v1 *host,
    const uint8_t *frame,
    size_t frame_size,
    const urp_launch_args_v1 *args);

#ifdef __cplusplus
}
#endif

#endif
