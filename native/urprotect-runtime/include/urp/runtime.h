#ifndef URP_RUNTIME_H
#define URP_RUNTIME_H

#include "urp/host_context.h"
#include "urp/payload_frame.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define URP_RUNTIME_MAX_SOURCE_SIZE URP_FRAME_MAX_SOURCE_SIZE
#define URP_RUNTIME_MAX_ENTRY_NAME URP_FRAME_MAX_SOURCE_NAME
#define URP_RUNTIME_FRAME_VERSION_V1 URP_FRAME_VERSION_V1
#define URP_RUNTIME_FRAME_VERSION_V2 URP_FRAME_VERSION_V2
#define URP_RUNTIME_FRAME_VERSION_V3 URP_FRAME_VERSION_V3
#define URP_RUNTIME_FRAME_COMMON_HEADER_SIZE URP_FRAME_COMMON_HEADER_SIZE
#define URP_RUNTIME_FRAME_V1_HEADER_SIZE URP_FRAME_V1_HEADER_SIZE
#define URP_RUNTIME_FRAME_V2_HEADER_SIZE URP_FRAME_V2_HEADER_SIZE
#define URP_RUNTIME_FRAME_V2_HOST_ABI_OFFSET URP_FRAME_V2_HOST_ABI_OFFSET
#define URP_RUNTIME_FRAME_V2_RESERVED_BEFORE_CAPABILITIES_OFFSET \
    URP_FRAME_V2_RESERVED_BEFORE_CAPABILITIES_OFFSET
#define URP_RUNTIME_FRAME_V2_REQUIRED_CAPABILITIES_OFFSET \
    URP_FRAME_V2_REQUIRED_CAPABILITIES_OFFSET
#define URP_RUNTIME_FRAME_V2_ENTRY_NAME_SIZE_OFFSET \
    URP_FRAME_V2_ENTRY_NAME_SIZE_OFFSET
#define URP_RUNTIME_FRAME_V2_RESERVED_AFTER_ENTRY_NAME_SIZE_OFFSET \
    URP_FRAME_V2_RESERVED_AFTER_ENTRY_NAME_SIZE_OFFSET
#define URP_RUNTIME_FRAME_V3_PROFILE_OFFSET URP_FRAME_V3_PROFILE_OFFSET
#define URP_RUNTIME_FRAME_V3_RESERVED_OFFSET URP_FRAME_V3_RESERVED_OFFSET

/* Execute one verified HostContext frame through the supplied host contract. */
urp_status urp_runtime_execute_frame(
    const urp_host_context_v1 *host,
    const uint8_t *frame,
    size_t frame_size,
    const urp_launch_args_v1 *args);

/* Execute the current profile frame discovered in an appended wrapper image. */
urp_status urp_runtime_execute_wrapper(
    const urp_host_context_v1 *host,
    const uint8_t *wrapper,
    size_t wrapper_size,
    const urp_launch_args_v1 *args);

#ifdef __cplusplus
}
#endif

#endif
