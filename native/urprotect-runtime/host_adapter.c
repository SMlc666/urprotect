#define _GNU_SOURCE

#include "urp/host_adapter.h"
#include "host_image_validation.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define URP_MEMFD_CLOEXEC 1U
#define URP_MEMFD_ALLOW_SEALING 2U
#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#endif
#ifndef F_GET_SEALS
#define F_GET_SEALS 1034
#endif
#ifndef F_SEAL_SEAL
#define F_SEAL_SEAL 0x0001
#endif
#ifndef F_SEAL_SHRINK
#define F_SEAL_SHRINK 0x0002
#endif
#ifndef F_SEAL_GROW
#define F_SEAL_GROW 0x0004
#endif
#ifndef F_SEAL_WRITE
#define F_SEAL_WRITE 0x0008
#endif
#define URP_REQUIRED_IMAGE_SEALS (F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL)
typedef struct urp_fd_image {
    void *dl_handle;
    int fd;
} urp_fd_image;

#if defined(URP_HOST_ADAPTER_TEST_DIAGNOSTICS)
static size_t urp_memfd_create_attempt_count;
#endif

static int urp_write_all(int fd, const void *bytes, size_t size)
{
    const uint8_t *source = (const uint8_t *)bytes;
    size_t offset = 0U;
    while (offset < size) {
        ssize_t written = write(fd, source + offset, size - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return 0;
        }
        offset += (size_t)written;
    }
    return 1;
}

static int urp_seal_image_fd(int fd)
{
    const int required_seals = URP_REQUIRED_IMAGE_SEALS;
    if (fcntl(fd, F_ADD_SEALS, required_seals) != 0) {
        return 0;
    }

    int seals = fcntl(fd, F_GET_SEALS);
    return seals >= 0 && (seals & required_seals) == required_seals;
}

static urp_status urp_adapter_load_image(
    void *userdata,
    const void *bytes,
    size_t size,
    uint32_t flags,
    urp_image_handle *out_handle)
{
    (void)userdata;
    if (out_handle == NULL) {
        return URP_STATUS_INVALID_ARGUMENT;
    }
    *out_handle = 0U;
    if ((flags & URP_LOAD_IMAGE_IMMUTABLE) == 0U) {
        return URP_STATUS_INVALID_ARGUMENT;
    }

    size_t dependency_count = 0U;
    urp_status validation = urp_host_image_validate(bytes, size, &dependency_count);
    if (validation != URP_STATUS_OK) {
        return validation;
    }
    if (dependency_count == 2U) {
        static const char *const loader_variables[] = {
            "LD_LIBRARY_PATH",
            "LD_PRELOAD",
            "LD_AUDIT"
        };
        for (size_t index = 0U;
             index < sizeof(loader_variables) / sizeof(loader_variables[0]);
             ++index) {
            const char *value = getenv(loader_variables[index]);
            if (value != NULL && value[0] != '\0') {
                return URP_STATUS_UNSUPPORTED;
            }
        }
    }

#if defined(URP_HOST_ADAPTER_TEST_DIAGNOSTICS)
    ++urp_memfd_create_attempt_count;
#endif
    long fd_result = syscall(
        SYS_memfd_create,
        "urprotect-host-image",
        URP_MEMFD_CLOEXEC | URP_MEMFD_ALLOW_SEALING);
    if (fd_result < 0 || fd_result > INT_MAX) {
        if (fd_result >= 0) {
            (void)close((int)fd_result);
        }
        return URP_STATUS_LOAD_FAILED;
    }
    int fd = (int)fd_result;
    if (!urp_write_all(fd, bytes, size)
        || fchmod(fd, S_IRUSR | S_IWUSR | S_IXUSR) != 0
        || lseek(fd, 0, SEEK_SET) < 0
        || !urp_seal_image_fd(fd)) {
        (void)close(fd);
        return URP_STATUS_LOAD_FAILED;
    }

    char fd_path[64];
    int path_size = snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    if (path_size < 0 || (size_t)path_size >= sizeof(fd_path)) {
        (void)close(fd);
        return URP_STATUS_LOAD_FAILED;
    }

    (void)dlerror();
    void *dl_handle = dlopen(fd_path, RTLD_NOW | RTLD_LOCAL);
    if (dl_handle == NULL) {
#if defined(URP_HOST_ADAPTER_TEST_DIAGNOSTICS)
        const char *loader_error = dlerror();
        (void)fprintf(
            stderr,
            "HostContext adapter dlopen failed: %s\n",
            loader_error != NULL ? loader_error : "unknown loader error");
#endif
        (void)close(fd);
        return URP_STATUS_LOAD_FAILED;
    }

    urp_fd_image *image = (urp_fd_image *)calloc(1U, sizeof(*image));
    if (image == NULL) {
        (void)dlclose(dl_handle);
        (void)close(fd);
        return URP_STATUS_LOAD_FAILED;
    }
    image->dl_handle = dl_handle;
    image->fd = fd;
    *out_handle = (urp_image_handle)(uintptr_t)image;
    return URP_STATUS_OK;
}

static urp_status urp_adapter_lookup_symbol(
    void *userdata,
    urp_image_handle handle,
    const char *name,
    const char *version,
    uintptr_t *out_address)
{
    (void)userdata;
    if (handle == 0U || name == NULL || version != NULL || out_address == NULL) {
        return URP_STATUS_INVALID_ARGUMENT;
    }

    urp_fd_image *image = (urp_fd_image *)(uintptr_t)handle;
    (void)dlerror();
    void *symbol = dlsym(image->dl_handle, name);
    const char *error = dlerror();
    if (symbol == NULL || error != NULL) {
        return URP_STATUS_SYMBOL_NOT_FOUND;
    }
    *out_address = (uintptr_t)symbol;
    return URP_STATUS_OK;
}

static urp_status urp_adapter_release_image(void *userdata, urp_image_handle handle)
{
    (void)userdata;
    if (handle == 0U) {
        return URP_STATUS_INVALID_ARGUMENT;
    }

    urp_fd_image *image = (urp_fd_image *)(uintptr_t)handle;
    int dl_result = dlclose(image->dl_handle);
    int close_result = close(image->fd);
    free(image);
    return dl_result == 0 && close_result == 0
        ? URP_STATUS_OK
        : URP_STATUS_LOAD_FAILED;
}

int urp_host_adapter_image_is_sealed(urp_image_handle handle)
{
    if (handle == 0U) {
        return 0;
    }

    const urp_fd_image *image = (const urp_fd_image *)(uintptr_t)handle;
    int seals = fcntl(image->fd, F_GET_SEALS);
    return seals >= 0 && (seals & URP_REQUIRED_IMAGE_SEALS) == URP_REQUIRED_IMAGE_SEALS;
}

#if defined(URP_HOST_ADAPTER_TEST_DIAGNOSTICS)
size_t urp_host_adapter_memfd_create_attempts(void)
{
    return urp_memfd_create_attempt_count;
}
#endif

static urp_status urp_adapter_emit_diagnostic(
    void *userdata,
    uint32_t code,
    const char *message)
{
    (void)userdata;
    (void)code;
    (void)message;
    return URP_STATUS_OK;
}

void urp_host_adapter_init(urp_host_adapter_v1 *adapter)
{
    if (adapter == NULL) {
        return;
    }
    memset(adapter, 0, sizeof(*adapter));
    adapter->context.abi_version = URP_HOST_ABI_VERSION;
    adapter->context.struct_size = sizeof(adapter->context);
    adapter->context.capabilities = URP_HOST_CAP_LOAD_IMAGE
        | URP_HOST_CAP_LOOKUP_SYMBOL
        | URP_HOST_CAP_RELEASE_IMAGE
        | URP_HOST_CAP_EMIT_DIAGNOSTIC;
    adapter->context.userdata = adapter;
    adapter->context.load_image = urp_adapter_load_image;
    adapter->context.lookup_symbol = urp_adapter_lookup_symbol;
    adapter->context.release_image = urp_adapter_release_image;
    adapter->context.emit_diagnostic = urp_adapter_emit_diagnostic;
}
