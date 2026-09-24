#include "urp/host_context.h"
#include "urp/payload_frame.h"

#include <stddef.h>
#include <stdio.h>

_Static_assert(sizeof(urp_host_context_v1) == 56U, "HostContext ABI size changed");
_Static_assert(sizeof(urp_launch_args_v1) == 32U, "launch-args ABI size changed");
_Static_assert(offsetof(urp_host_context_v1, capabilities) == 8U, "HostContext capabilities offset changed");
_Static_assert(offsetof(urp_host_context_v1, load_image) == 24U, "HostContext load callback offset changed");
_Static_assert(offsetof(urp_launch_args_v1, argc) == 8U, "launch-args argc offset changed");

int main(void)
{
    printf(
        "{\"hostContextSize\":%zu,\"launchArgsSize\":%zu,"
        "\"hostAbiVersion\":%u,\"frameV1HeaderSize\":%u,"
        "\"frameV2HeaderSize\":%u,\"frameV3HeaderSize\":%u,"
        "\"frameTrailerSize\":%u,"
        "\"frameSha256Size\":%u,\"v2AbiOffset\":%u,"
        "\"v2CapabilitiesOffset\":%u,\"v2EntryNameSizeOffset\":%u,"
        "\"v3ProfileOffset\":%u,\"v3ReservedOffset\":%u}\n",
        sizeof(urp_host_context_v1),
        sizeof(urp_launch_args_v1),
        URP_HOST_ABI_VERSION,
        URP_FRAME_V1_HEADER_SIZE,
        URP_FRAME_V2_HEADER_SIZE,
        URP_FRAME_V3_HEADER_SIZE,
        URP_FRAME_TRAILER_SIZE,
        URP_FRAME_SHA256_SIZE,
        URP_FRAME_V2_HOST_ABI_OFFSET,
        URP_FRAME_V2_REQUIRED_CAPABILITIES_OFFSET,
        URP_FRAME_V2_ENTRY_NAME_SIZE_OFFSET,
        URP_FRAME_V3_PROFILE_OFFSET,
        URP_FRAME_V3_RESERVED_OFFSET);
    return ferror(stdout) == 0 ? 0 : 1;
}
