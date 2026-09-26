#define _GNU_SOURCE

#include "urp/host_adapter.h"
#include "host_image_validation.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#if defined(__GLIBC__)
#include <gnu/libc-version.h>
#include <link.h>
#endif

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
typedef struct urp_image_thread_record {
    pthread_t thread;
    urp_image_thread_handle handle;
    int joined; /* 0=registered, -1=join in progress, 1=joined */
    struct urp_image_thread_record *next;
} urp_image_thread_record;

typedef struct urp_fd_image {
    void *dl_handle;
    urp_image_handle handle;
    int fd;
    pthread_t owner;
    int release_started;
    int release_active;
    urp_image_thread_record *threads;
    struct urp_fd_image *registry_next;
} urp_fd_image;

static pthread_mutex_t urp_image_registry_mutex = PTHREAD_MUTEX_INITIALIZER;
static urp_fd_image *urp_image_registry;
#if defined(__GLIBC__)
static urp_image_thread_handle urp_next_thread_handle = 1U;
#endif
static urp_image_handle urp_next_image_handle = 1U;

static urp_fd_image *urp_find_image_locked(urp_image_handle handle)
{
    for (urp_fd_image *image = urp_image_registry; image != NULL; image = image->registry_next) {
        if (image->handle == handle) {
            return image;
        }
    }
    return NULL;
}

#if defined(URP_HOST_ADAPTER_TEST_DIAGNOSTICS)
static _Atomic size_t urp_memfd_create_attempt_count;
static _Atomic int urp_fail_next_thread_create;
static _Atomic int urp_fail_next_thread_join;
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
    (void)atomic_fetch_add_explicit(&urp_memfd_create_attempt_count, 1U, memory_order_relaxed);
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
    image->owner = pthread_self();
    (void)pthread_mutex_lock(&urp_image_registry_mutex);
    if (urp_next_image_handle == 0U || urp_next_image_handle == UINT64_MAX) {
        (void)pthread_mutex_unlock(&urp_image_registry_mutex);
        (void)dlclose(dl_handle);
        (void)close(fd);
        free(image);
        return URP_STATUS_LOAD_FAILED;
    }
    image->handle = urp_next_image_handle++;
    image->registry_next = urp_image_registry;
    urp_image_registry = image;
    (void)pthread_mutex_unlock(&urp_image_registry_mutex);
    *out_handle = image->handle;
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

    (void)pthread_mutex_lock(&urp_image_registry_mutex);
    urp_fd_image *image = urp_find_image_locked(handle);
    if (image == NULL || image->release_started) {
        (void)pthread_mutex_unlock(&urp_image_registry_mutex);
        return URP_STATUS_INVALID_ARGUMENT;
    }
    (void)dlerror();
    void *symbol = dlsym(image->dl_handle, name);
    const char *error = dlerror();
    if (symbol == NULL || error != NULL) {
        (void)pthread_mutex_unlock(&urp_image_registry_mutex);
        return URP_STATUS_SYMBOL_NOT_FOUND;
    }
    *out_address = (uintptr_t)symbol;
    (void)pthread_mutex_unlock(&urp_image_registry_mutex);
    return URP_STATUS_OK;
}

#if defined(__GLIBC__)
static urp_status urp_adapter_create_image_thread(
    void *userdata,
    urp_image_handle handle,
    void *(*routine)(void *),
    void *argument,
    urp_image_thread_handle *out_thread)
{
    (void)userdata;
    if (out_thread == NULL) {
        return URP_STATUS_INVALID_ARGUMENT;
    }
    *out_thread = 0U;
    if (handle == 0U || routine == NULL) {
        return URP_STATUS_INVALID_ARGUMENT;
    }
    urp_image_thread_record *record = calloc(1U, sizeof(*record));
    if (record == NULL) {
        return URP_STATUS_LOAD_FAILED;
    }
    (void)pthread_mutex_lock(&urp_image_registry_mutex);
    urp_fd_image *image = urp_find_image_locked(handle);
    if (image == NULL || image->release_started || !pthread_equal(image->owner, pthread_self())) {
        (void)pthread_mutex_unlock(&urp_image_registry_mutex);
        free(record);
        return image == NULL ? URP_STATUS_INVALID_ARGUMENT : URP_STATUS_UNSUPPORTED;
    }
    /* A routine must resolve to this dlopen root, not libc or another DSO. */
    struct link_map *root_map = NULL;
    struct link_map *routine_map = NULL;
    Dl_info routine_info;
    if (dlinfo(image->dl_handle, RTLD_DI_LINKMAP, &root_map) != 0
        || dladdr1((void *)(uintptr_t)routine, &routine_info, (void **)&routine_map, RTLD_DL_LINKMAP) == 0
        || root_map == NULL || routine_map != root_map) {
        (void)pthread_mutex_unlock(&urp_image_registry_mutex);
        free(record);
        return URP_STATUS_UNSUPPORTED;
    }
    if (urp_next_thread_handle == 0U || urp_next_thread_handle == UINT64_MAX) {
        /* Never recycle opaque handles: exhaustion permanently closes creation. */
        (void)pthread_mutex_unlock(&urp_image_registry_mutex);
        free(record);
        return URP_STATUS_LOAD_FAILED;
    }
    record->handle = urp_next_thread_handle++;
    record->next = image->threads;
    image->threads = record; /* Reserve image ownership before the thread can run. */
#if defined(URP_HOST_ADAPTER_TEST_DIAGNOSTICS)
    int result = atomic_exchange_explicit(&urp_fail_next_thread_create, 0, memory_order_relaxed)
        ? EAGAIN
        : pthread_create(&record->thread, NULL, routine, argument);
#else
    int result = pthread_create(&record->thread, NULL, routine, argument);
#endif
    if (result != 0) {
        image->threads = record->next;
        (void)pthread_mutex_unlock(&urp_image_registry_mutex);
        free(record);
        return URP_STATUS_LOAD_FAILED;
    }
    *out_thread = record->handle;
    (void)pthread_mutex_unlock(&urp_image_registry_mutex);
    return URP_STATUS_OK;
}

static urp_status urp_adapter_join_image_thread(
    void *userdata,
    urp_image_handle handle,
    urp_image_thread_handle thread_handle,
    void **out_result)
{
    (void)userdata;
    if (handle == 0U || thread_handle == 0U || out_result == NULL) {
        return URP_STATUS_INVALID_ARGUMENT;
    }
    *out_result = NULL;
    (void)pthread_mutex_lock(&urp_image_registry_mutex);
    urp_fd_image *image = urp_find_image_locked(handle);
    urp_image_thread_record *record = NULL;
    if (image != NULL) {
        for (record = image->threads; record != NULL; record = record->next) {
            if (record->handle == thread_handle) break;
        }
    }
    if (image == NULL || record == NULL || record->joined || image->release_started
        || !pthread_equal(image->owner, pthread_self())
        || pthread_equal(record->thread, pthread_self())) {
        (void)pthread_mutex_unlock(&urp_image_registry_mutex);
        return URP_STATUS_INVALID_ARGUMENT;
    }
    record->joined = -1;
    (void)pthread_mutex_unlock(&urp_image_registry_mutex);
    void *result = NULL;
#if defined(URP_HOST_ADAPTER_TEST_DIAGNOSTICS)
    int join_status = atomic_exchange_explicit(&urp_fail_next_thread_join, 0, memory_order_relaxed)
        ? EINVAL
        : pthread_join(record->thread, &result);
#else
    int join_status = pthread_join(record->thread, &result);
#endif
    (void)pthread_mutex_lock(&urp_image_registry_mutex);
    if (join_status != 0) {
        record->joined = 0;
        (void)pthread_mutex_unlock(&urp_image_registry_mutex);
        return URP_STATUS_LOAD_FAILED;
    }
    record->joined = 1;
    *out_result = result;
    (void)pthread_mutex_unlock(&urp_image_registry_mutex);
    return URP_STATUS_OK;
}
#endif

static urp_status urp_adapter_release_image(void *userdata, urp_image_handle handle)
{
    (void)userdata;
    if (handle == 0U) return URP_STATUS_INVALID_ARGUMENT;
    (void)pthread_mutex_lock(&urp_image_registry_mutex);
    urp_fd_image *image = urp_find_image_locked(handle);
    if (image == NULL || !pthread_equal(image->owner, pthread_self())) {
        (void)pthread_mutex_unlock(&urp_image_registry_mutex);
        return URP_STATUS_INVALID_ARGUMENT;
    }
    if (image->release_active) {
        (void)pthread_mutex_unlock(&urp_image_registry_mutex);
        return URP_STATUS_LOAD_FAILED;
    }
    image->release_active = 1;
    image->release_started = 1;
    (void)pthread_mutex_unlock(&urp_image_registry_mutex);

    for (;;) {
        (void)pthread_mutex_lock(&urp_image_registry_mutex);
        urp_image_thread_record *record = image->threads;
        while (record != NULL && record->joined == 1) record = record->next;
        if (record == NULL) {
            (void)pthread_mutex_unlock(&urp_image_registry_mutex);
            break;
        }
        if (record->joined == -1) {
            image->release_active = 0;
            (void)pthread_mutex_unlock(&urp_image_registry_mutex);
            return URP_STATUS_LOAD_FAILED;
        }
        record->joined = -1;
        (void)pthread_mutex_unlock(&urp_image_registry_mutex);
#if defined(URP_HOST_ADAPTER_TEST_DIAGNOSTICS)
        int join_status = atomic_exchange_explicit(&urp_fail_next_thread_join, 0, memory_order_relaxed)
            ? EINVAL
            : pthread_join(record->thread, NULL);
#else
        int join_status = pthread_join(record->thread, NULL);
#endif
        (void)pthread_mutex_lock(&urp_image_registry_mutex);
        record->joined = join_status == 0 ? 1 : 0;
        (void)pthread_mutex_unlock(&urp_image_registry_mutex);
        if (join_status != 0) {
            (void)pthread_mutex_lock(&urp_image_registry_mutex);
            image->release_active = 0;
            (void)pthread_mutex_unlock(&urp_image_registry_mutex);
            return URP_STATUS_LOAD_FAILED;
        }
    }

    int dl_result = dlclose(image->dl_handle);
    if (dl_result != 0) {
        /* Keep the mapping and fd pinned when loader teardown reports failure. */
        (void)pthread_mutex_lock(&urp_image_registry_mutex);
        image->release_active = 0;
        (void)pthread_mutex_unlock(&urp_image_registry_mutex);
        return URP_STATUS_LOAD_FAILED;
    }
    int close_result = close(image->fd);
    (void)pthread_mutex_lock(&urp_image_registry_mutex);
    urp_fd_image **cursor = &urp_image_registry;
    while (*cursor != NULL && *cursor != image) cursor = &(*cursor)->registry_next;
    if (*cursor == image) *cursor = image->registry_next;
    urp_image_thread_record *thread = image->threads;
    while (thread != NULL) {
        urp_image_thread_record *next = thread->next;
        free(thread);
        thread = next;
    }
    (void)pthread_mutex_unlock(&urp_image_registry_mutex);
    free(image);
    return close_result == 0 ? URP_STATUS_OK : URP_STATUS_LOAD_FAILED;
}

int urp_host_adapter_image_is_sealed(urp_image_handle handle)
{
    if (handle == 0U) {
        return 0;
    }

    (void)pthread_mutex_lock(&urp_image_registry_mutex);
    const urp_fd_image *image = urp_find_image_locked(handle);
    if (image == NULL) { (void)pthread_mutex_unlock(&urp_image_registry_mutex); return 0; }
    int seals = fcntl(image->fd, F_GET_SEALS);
    int sealed = seals >= 0 && (seals & URP_REQUIRED_IMAGE_SEALS) == URP_REQUIRED_IMAGE_SEALS;
    (void)pthread_mutex_unlock(&urp_image_registry_mutex);
    return sealed;
}

#if defined(URP_HOST_ADAPTER_TEST_DIAGNOSTICS)
size_t urp_host_adapter_memfd_create_attempts(void)
{
    return atomic_load_explicit(&urp_memfd_create_attempt_count, memory_order_relaxed);
}

void urp_host_adapter_test_fail_next_thread_create(void)
{
    atomic_store_explicit(&urp_fail_next_thread_create, 1, memory_order_relaxed);
}

void urp_host_adapter_test_fail_next_thread_join(void)
{
    atomic_store_explicit(&urp_fail_next_thread_join, 1, memory_order_relaxed);
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
#if defined(__GLIBC__)
    /* Build/runtime identity is checked; other libc implementations get no bit. */
    if (gnu_get_libc_version() != NULL) {
        adapter->context.capabilities |= URP_HOST_CAP_THREAD_LIFETIME;
        adapter->context.create_image_thread = urp_adapter_create_image_thread;
        adapter->context.join_image_thread = urp_adapter_join_image_thread;
    }
#endif
}
