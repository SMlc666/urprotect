#define _GNU_SOURCE

#include "urp/host_adapter.h"
#include "urp/runtime.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define URP_HOST_CONTEXT_LAUNCHER_MARKER "URPROTECT-AARCH64-HOST-CONTEXT-V3"

static const char urp_host_context_launcher_marker[] =
    URP_HOST_CONTEXT_LAUNCHER_MARKER;

static int urp_read_self(uint8_t **bytes_out, size_t *size_out)
{
    *bytes_out = NULL;
    *size_out = 0U;

    int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return 0;
    }

    struct stat info;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size <= 0) {
        (void)close(fd);
        return 0;
    }

    uint64_t size_u64 = (uint64_t)info.st_size;
    if (size_u64 > URP_FRAME_MAX_WRAPPER_SIZE || size_u64 > (uint64_t)SIZE_MAX) {
        (void)close(fd);
        return 0;
    }

    size_t size = (size_t)size_u64;
    uint8_t *bytes = (uint8_t *)malloc(size);
    if (bytes == NULL) {
        (void)close(fd);
        return 0;
    }

    size_t offset = 0U;
    while (offset < size) {
        ssize_t count = read(fd, bytes + offset, size - offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            free(bytes);
            (void)close(fd);
            return 0;
        }
        offset += (size_t)count;
    }

    (void)close(fd);
    *bytes_out = bytes;
    *size_out = size;
    return 1;
}

static int urp_process_status(urp_status status)
{
    if (status >= 0) {
        return status <= 255 ? (int)status : 255;
    }
    if (status == URP_STATUS_INTEGRITY_FAILURE) {
        return 5;
    }
    return 4;
}

int main(int argc, char **argv, char **envp)
{
    volatile const char *marker = urp_host_context_launcher_marker;
    size_t marker_length = sizeof(URP_HOST_CONTEXT_LAUNCHER_MARKER) - 1U;
    if (marker[0] != 'U' || marker[marker_length - 1U] != '3') {
        fputs("LauncherAbiMismatch: invalid HostContext launcher marker\n", stderr);
        return 4;
    }

    uint8_t *wrapper = NULL;
    size_t wrapper_size = 0U;
    if (!urp_read_self(&wrapper, &wrapper_size)) {
        fputs("InputIoFailure: could not inspect /proc/self/exe\n", stderr);
        return 3;
    }

    urp_host_adapter_v1 adapter;
    urp_host_adapter_init(&adapter);
    urp_launch_args_v1 args = {
        .abi_version = URP_HOST_ABI_VERSION,
        .struct_size = sizeof(args),
        .argc = argc > 0 ? (uint32_t)argc : 0U,
        .argv = (const char *const *)argv,
        .envp = (const char *const *)envp,
    };

    urp_status status = urp_runtime_execute_wrapper(
        &adapter.context,
        wrapper,
        wrapper_size,
        &args);
    free(wrapper);
    return urp_process_status(status);
}
