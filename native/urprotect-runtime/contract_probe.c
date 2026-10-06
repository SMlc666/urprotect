#include "urp/host_context.h"
#include "urp/payload_frame.h"

#include <stddef.h>
#include <stdio.h>

_Static_assert(sizeof(urp_host_context_v1) == 72U, "HostContext current ABI size changed");
_Static_assert(sizeof(urp_launch_args_v1) == 40U, "current launch-args ABI size changed");
_Static_assert(offsetof(urp_host_context_v1, capabilities) == 8U, "HostContext capabilities offset changed");
_Static_assert(offsetof(urp_host_context_v1, load_image) == 24U, "HostContext load callback offset changed");
_Static_assert(offsetof(urp_launch_args_v1, argc) == 8U, "launch-args argc offset changed");

int main(void)
{
    _Static_assert(offsetof(urp_host_context_v1, create_image_thread) == 56U, "thread callback offset changed");
    _Static_assert(offsetof(urp_launch_args_v1, image) == 32U, "image handle offset changed");
    printf(
        "{\"hostContextSize\":%zu,\"launchArgsSize\":%zu,"
        "\"hostAbiVersion\":%u,\"frameVersion\":%u,"
        "\"frameHeaderSize\":%u,\"frameTrailerSize\":%u,"
        "\"frameSha256Size\":%u,\"hostAbiOffset\":%u,"
        "\"requiredCapabilitiesOffset\":%u,\"entryNameSizeOffset\":%u,"
        "\"profileOffset\":%u,\"reservedOffset\":%u,\"threadCreateOffset\":%u,"
        "\"threadJoinOffset\":%u,\"launchImageOffset\":%u}\n",
        sizeof(urp_host_context_v1),
        sizeof(urp_launch_args_v1),
        URP_HOST_ABI_VERSION,
        URP_FRAME_VERSION,
        URP_FRAME_HEADER_SIZE,
        URP_FRAME_TRAILER_SIZE,
        URP_FRAME_SHA256_SIZE,
        URP_FRAME_HOST_ABI_OFFSET,
        URP_FRAME_REQUIRED_CAPABILITIES_OFFSET,
        URP_FRAME_ENTRY_NAME_SIZE_OFFSET,
        URP_FRAME_PROFILE_OFFSET,
        URP_FRAME_RESERVED_OFFSET,
        (unsigned int)offsetof(urp_host_context_v1, create_image_thread),
        (unsigned int)offsetof(urp_host_context_v1, join_image_thread),
        (unsigned int)offsetof(urp_launch_args_v1, image));
    return ferror(stdout) == 0 ? 0 : 1;
}
