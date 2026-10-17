#define _GNU_SOURCE

#include "urp/host_adapter.h"
#include "host_image_validation.h"
#include "sha256.h"

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
#include <sys/sysmacros.h>
#endif
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

typedef struct urp_loaded_provider {
    void *dl_handle;
    int fd;
#if defined(__GLIBC__)
    Lmid_t namespace_id;
    struct link_map *link_map;
#endif
    size_t references;
    char soname[URP_HOST_PROVIDER_SONAME_CAPACITY];
    char build_id_hex[URP_HOST_PROVIDER_BUILD_ID_HEX_CAPACITY];
    char sha256_hex[URP_HOST_PROVIDER_SHA256_HEX_CAPACITY];
    uintptr_t table_address;
    uint8_t table_bytes[16];
} urp_loaded_provider;

typedef struct urp_fd_image {
    void *dl_handle;
    urp_image_handle handle;
    int fd;
    urp_loaded_provider *provider;
    pthread_t owner;
    int release_started;
    int release_active;
    urp_image_thread_record *threads;
    struct urp_fd_image *registry_next;
} urp_fd_image;

static pthread_mutex_t urp_image_registry_mutex = PTHREAD_MUTEX_INITIALIZER;
static urp_fd_image *urp_image_registry;
#if defined(__GLIBC__)
static urp_loaded_provider *urp_active_provider;
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
static _Atomic size_t urp_loader_attempt_count;
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

static int urp_create_sealed_memfd(
    const char *name,
    const void *bytes,
    size_t size,
    mode_t mode)
{
    if (name == NULL || bytes == NULL || size == 0U) return -1;
#if defined(URP_HOST_ADAPTER_TEST_DIAGNOSTICS)
    (void)atomic_fetch_add_explicit(&urp_memfd_create_attempt_count, 1U, memory_order_relaxed);
#endif
    long fd_result = syscall(
        SYS_memfd_create,
        name,
        URP_MEMFD_CLOEXEC | URP_MEMFD_ALLOW_SEALING);
    if (fd_result < 0 || fd_result > INT_MAX) {
        if (fd_result >= 0) (void)close((int)fd_result);
        return -1;
    }
    int fd = (int)fd_result;
    if (!urp_write_all(fd, bytes, size)
        || fchmod(fd, mode) != 0
        || lseek(fd, 0, SEEK_SET) < 0
        || !urp_seal_image_fd(fd)) {
        (void)close(fd);
        return -1;
    }
    return fd;
}

#if defined(__GLIBC__)
static int urp_read_provider_file(
    const char *path,
    uint8_t **bytes_out,
    size_t *size_out)
{
    const size_t maximum_size = 64U * 1024U * 1024U;
    if (path == NULL || bytes_out == NULL || size_out == NULL) return 0;
    *bytes_out = NULL;
    *size_out = 0U;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return 0;
    struct stat info;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode)
        || info.st_size <= 0 || (uint64_t)info.st_size > (uint64_t)maximum_size
        || (uint64_t)info.st_size > (uint64_t)SIZE_MAX) {
        (void)close(fd);
        return 0;
    }
    size_t size = (size_t)info.st_size;
    uint8_t *bytes = (uint8_t *)malloc(size);
    if (bytes == NULL) {
        (void)close(fd);
        return 0;
    }
    size_t offset = 0U;
    while (offset < size) {
        ssize_t count = read(fd, bytes + offset, size - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            free(bytes);
            (void)close(fd);
            return 0;
        }
        offset += (size_t)count;
    }
    uint8_t extra;
    ssize_t extra_count;
    do {
        extra_count = read(fd, &extra, sizeof(extra));
    } while (extra_count < 0 && errno == EINTR);
    (void)close(fd);
    if (extra_count != 0) {
        free(bytes);
        return 0;
    }
    *bytes_out = bytes;
    *size_out = size;
    return 1;
}

static void urp_sha256_hex(const uint8_t *bytes, size_t size, char output[65])
{
    static const char hex[] = "0123456789abcdef";
    uint8_t digest[32];
    urp_sha256_context context;
    urp_sha256_init(&context);
    urp_sha256_update(&context, bytes, size);
    urp_sha256_final(&context, digest);
    for (size_t index = 0U; index < sizeof(digest); ++index) {
        output[index * 2U] = hex[digest[index] >> 4U];
        output[(index * 2U) + 1U] = hex[digest[index] & 0x0fU];
    }
    output[64] = '\0';
}

#endif /* __GLIBC__: provider file acquisition and digest */

static int urp_is_hex_string(const char *value, size_t expected_length)
{
    if (value == NULL || strlen(value) != expected_length) return 0;
    for (size_t index = 0U; index < expected_length; ++index) {
        char c = value[index];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
            || (c >= 'A' && c <= 'F'))) return 0;
    }
    return 1;
}

#if defined(__GLIBC__)
static int urp_hex_equal(const char *left, const char *right, size_t length)
{
    if (left == NULL || right == NULL) return 0;
    for (size_t index = 0U; index < length; ++index) {
        char a = left[index];
        char b = right[index];
        if (a >= 'A' && a <= 'F') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'F') b = (char)(b - 'A' + 'a');
        if (a != b) return 0;
    }
    return 1;
}

#endif /* __GLIBC__: provider digest comparison */

#if defined(__GLIBC__)
typedef struct urp_soname_search {
    const char *soname;
    size_t matches;
    int malformed;
} urp_soname_search;

static int urp_loaded_range_contains(
    const struct dl_phdr_info *info,
    uintptr_t address,
    size_t length)
{
    if (length > UINTPTR_MAX - address) return 0;
    uintptr_t end = address + length;
    for (ElfW(Half) index = 0U; index < info->dlpi_phnum; ++index) {
        const ElfW(Phdr) *header = &info->dlpi_phdr[index];
        if (header->p_type != PT_LOAD || header->p_memsz > UINTPTR_MAX
            || info->dlpi_addr > UINTPTR_MAX - (uintptr_t)header->p_vaddr) continue;
        uintptr_t start = (uintptr_t)info->dlpi_addr + (uintptr_t)header->p_vaddr;
        if (header->p_memsz > UINTPTR_MAX - start) continue;
        uintptr_t segment_end = start + (uintptr_t)header->p_memsz;
        if (address >= start && end <= segment_end) return 1;
    }
    return 0;
}

static int urp_count_loaded_soname_callback(
    struct dl_phdr_info *info,
    size_t size,
    void *userdata)
{
    (void)size;
    urp_soname_search *search = (urp_soname_search *)userdata;
    const ElfW(Phdr) *dynamic_header = NULL;
    for (ElfW(Half) index = 0U; index < info->dlpi_phnum; ++index) {
        if (info->dlpi_phdr[index].p_type == PT_DYNAMIC) {
            if (dynamic_header != NULL) {
                search->malformed = 1;
                return 1;
            }
            dynamic_header = &info->dlpi_phdr[index];
        }
    }
    if (dynamic_header == NULL || dynamic_header->p_memsz < sizeof(ElfW(Dyn))
        || dynamic_header->p_memsz / sizeof(ElfW(Dyn)) > (ElfW(Xword))(1U << 20)
        || info->dlpi_addr > UINTPTR_MAX - (uintptr_t)dynamic_header->p_vaddr) {
        return 0;
    }
    uintptr_t dynamic_address = (uintptr_t)info->dlpi_addr + (uintptr_t)dynamic_header->p_vaddr;
    size_t dynamic_bytes = (size_t)dynamic_header->p_memsz;
    if (!urp_loaded_range_contains(info, dynamic_address, dynamic_bytes)) return 0;
    const ElfW(Dyn) *dynamic = (const ElfW(Dyn) *)dynamic_address;
    size_t count = dynamic_bytes / sizeof(*dynamic);
    uintptr_t string_table_value = 0U;
    size_t string_table_size = 0U;
    size_t soname_offset = 0U;
    int has_string_table = 0;
    int has_string_table_size = 0;
    int has_soname = 0;
    int terminated = 0;
    for (size_t index = 0U; index < count; ++index) {
        if (dynamic[index].d_tag == DT_NULL) {
            terminated = 1;
            break;
        }
        if (dynamic[index].d_tag == DT_STRTAB) {
            if (has_string_table) {
                search->malformed = 1;
                return 1;
            }
            string_table_value = (uintptr_t)dynamic[index].d_un.d_ptr;
            has_string_table = 1;
        } else if (dynamic[index].d_tag == DT_STRSZ) {
            if (has_string_table_size || dynamic[index].d_un.d_val > (ElfW(Xword))SIZE_MAX) {
                search->malformed = 1;
                return 1;
            }
            string_table_size = (size_t)dynamic[index].d_un.d_val;
            has_string_table_size = 1;
        } else if (dynamic[index].d_tag == DT_SONAME) {
            if (has_soname || dynamic[index].d_un.d_val > (ElfW(Xword))SIZE_MAX) {
                search->malformed = 1;
                return 1;
            }
            soname_offset = (size_t)dynamic[index].d_un.d_val;
            has_soname = 1;
        }
    }
    if (!terminated || !has_string_table || !has_string_table_size || !has_soname
        || soname_offset >= string_table_size) {
        return 0;
    }
    uintptr_t relative_string_table_address = 0U;
    int relative_address_valid = info->dlpi_addr <= UINTPTR_MAX - string_table_value;
    if (relative_address_valid) {
        relative_string_table_address = (uintptr_t)info->dlpi_addr + string_table_value;
    }
    int direct_address_valid = urp_loaded_range_contains(
        info, string_table_value, string_table_size);
    relative_address_valid = relative_address_valid
        && urp_loaded_range_contains(info, relative_string_table_address, string_table_size);
    if (direct_address_valid && relative_address_valid
        && string_table_value != relative_string_table_address) {
        search->malformed = 1;
        return 1;
    }
    if (!direct_address_valid && !relative_address_valid) return 0;
    uintptr_t string_table_address = direct_address_valid
        ? string_table_value : relative_string_table_address;
    const char *soname = (const char *)(string_table_address + soname_offset);
    size_t remaining = string_table_size - soname_offset;
    const char *terminator = (const char *)memchr(soname, '\0', remaining);
    if (terminator == NULL) {
        search->malformed = 1;
        return 1;
    }
    size_t length = (size_t)(terminator - soname);
    if (length == strlen(search->soname) && memcmp(soname, search->soname, length) == 0) {
        ++search->matches;
    }
    return 0;
}

static int urp_loaded_soname_count(const char *soname, size_t *count_out)
{
    urp_soname_search search = { .soname = soname, .matches = 0U, .malformed = 0 };
    (void)dl_iterate_phdr(urp_count_loaded_soname_callback, &search);
    if (search.malformed) return 0;
    *count_out = search.matches;
    return 1;
}

static int urp_mapping_matches_provider_fd(
    int provider_fd,
    uintptr_t address,
    size_t length,
    int require_read_only,
    int require_executable)
{
    struct stat info;
    if (provider_fd < 0 || length == 0U || length > UINTPTR_MAX - address
        || fstat(provider_fd, &info) != 0) return 0;
    uintptr_t end = address + length;
    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps == NULL) return 0;
    char line[4096];
    int matched = 0;
    while (fgets(line, (int)sizeof(line), maps) != NULL) {
        unsigned long long start_value;
        unsigned long long end_value;
        unsigned long long file_offset;
        unsigned long long inode;
        unsigned int device_major;
        unsigned int device_minor;
        char permissions[5] = {0};
        int fields = sscanf(line, "%llx-%llx %4s %llx %x:%x %llu",
            &start_value, &end_value, permissions, &file_offset,
            &device_major, &device_minor, &inode);
        (void)file_offset;
        if (fields != 7 || start_value > (unsigned long long)UINTPTR_MAX
            || end_value > (unsigned long long)UINTPTR_MAX
            || inode != (unsigned long long)info.st_ino
            || (dev_t)makedev(device_major, device_minor) != info.st_dev
            || address < (uintptr_t)start_value || end > (uintptr_t)end_value
            || permissions[3] != 'p') continue;
        if (require_read_only
            && (permissions[0] != 'r' || permissions[1] != '-' || permissions[2] != '-')) continue;
        if (require_executable
            && (permissions[1] == 'w' || permissions[2] != 'x')) continue;
        matched = 1;
        break;
    }
    if (fclose(maps) != 0) return 0;
    return matched;
}

static int urp_provider_runtime_image_valid(
    int fd,
    void *provider_handle,
    const urp_host_external_provider_facts *facts,
    uintptr_t *table_address_out,
    Lmid_t *namespace_id_out,
    struct link_map **link_map_out)
{
    if (fd < 0 || provider_handle == NULL || facts == NULL || table_address_out == NULL
        || namespace_id_out == NULL || link_map_out == NULL) return 0;
    Lmid_t namespace_id;
    struct link_map *provider_map = NULL;
    if (dlinfo(provider_handle, RTLD_DI_LMID, &namespace_id) != 0
        || namespace_id == LM_ID_BASE
        || dlinfo(provider_handle, RTLD_DI_LINKMAP, &provider_map) != 0
        || provider_map == NULL) return 0;
    (void)dlerror();
    void *table = dlsym(provider_handle, URP_HOST_EXTERNAL_TABLE_SYMBOL);
    struct link_map *table_map = NULL;
    Dl_info table_info;
    if (table == NULL || dlerror() != NULL
        || dladdr1(table, &table_info, (void **)&table_map, RTLD_DL_LINKMAP) == 0
        || table_map != provider_map) return 0;
    uintptr_t table_address = (uintptr_t)table;
    if (memcmp(table, facts->table_bytes, sizeof(facts->table_bytes)) != 0
        || !urp_mapping_matches_provider_fd(fd, table_address, sizeof(facts->table_bytes), 1, 0)) {
        return 0;
    }
    for (size_t index = 0U; index < 4U; ++index) {
        size_t byte_offset = index * sizeof(uint32_t);
        uint32_t raw_offset = (uint32_t)facts->table_bytes[byte_offset]
            | ((uint32_t)facts->table_bytes[byte_offset + 1U] << 8U)
            | ((uint32_t)facts->table_bytes[byte_offset + 2U] << 16U)
            | ((uint32_t)facts->table_bytes[byte_offset + 3U] << 24U);
        int64_t displacement = (raw_offset & UINT32_C(0x80000000)) != 0U
            ? (int64_t)raw_offset - INT64_C(0x100000000) : (int64_t)raw_offset;
        uintptr_t target_address;
        if (displacement < 0) {
            uint64_t magnitude = (uint64_t)(-displacement);
            if (magnitude > (uint64_t)table_address) return 0;
            target_address = table_address - (uintptr_t)magnitude;
        } else {
            uint64_t magnitude = (uint64_t)displacement;
            if (magnitude > (uint64_t)UINTPTR_MAX - table_address) return 0;
            target_address = table_address + (uintptr_t)magnitude;
        }
        if (!urp_mapping_matches_provider_fd(fd, target_address, 4U, 0, 1)) return 0;
    }
    *table_address_out = table_address;
    *namespace_id_out = namespace_id;
    *link_map_out = provider_map;
    return 1;
}

static int urp_provider_loader_environment_clean(void)
{
    static const char *const variables[] = { "LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT" };
    for (size_t index = 0U; index < sizeof(variables) / sizeof(variables[0]); ++index) {
        const char *value = getenv(variables[index]);
        if (value != NULL && value[0] != '\0') return 0;
    }
    return 1;
}
#endif

#if defined(__GLIBC__)
static urp_status urp_acquire_provider(
    urp_host_adapter_v1 *adapter,
    urp_loaded_provider **provider_out)
{
    *provider_out = NULL;
    if (adapter == NULL || adapter->provider_configured == 0U
        || !urp_provider_loader_environment_clean()) return URP_STATUS_UNSUPPORTED;

    uint8_t *provider_bytes = NULL;
    size_t provider_size = 0U;
    if (!urp_read_provider_file(adapter->provider_path, &provider_bytes, &provider_size)) {
        return URP_STATUS_LOAD_FAILED;
    }
    char actual_sha256[URP_HOST_PROVIDER_SHA256_HEX_CAPACITY];
    urp_sha256_hex(provider_bytes, provider_size, actual_sha256);
    if (!urp_hex_equal(actual_sha256, adapter->provider_sha256_hex, 64U)) {
        free(provider_bytes);
        return URP_STATUS_UNSUPPORTED;
    }
    urp_host_external_provider_facts facts;
    urp_status validation = urp_host_external_provider_validate(
        provider_bytes, provider_size, adapter->provider_soname,
        adapter->provider_build_id_hex, &facts);
    if (validation != URP_STATUS_OK) {
        free(provider_bytes);
        return URP_STATUS_UNSUPPORTED;
    }

    (void)pthread_mutex_lock(&urp_image_registry_mutex);
    if (urp_active_provider != NULL) {
        urp_loaded_provider *active = urp_active_provider;
        if (strcmp(active->soname, adapter->provider_soname) != 0
            || !urp_hex_equal(active->build_id_hex, adapter->provider_build_id_hex, 40U)
            || !urp_hex_equal(active->sha256_hex, adapter->provider_sha256_hex, 64U)
            || memcmp(active->table_bytes, facts.table_bytes, sizeof(active->table_bytes)) != 0
            || active->references == SIZE_MAX) {
            (void)pthread_mutex_unlock(&urp_image_registry_mutex);
            free(provider_bytes);
            return URP_STATUS_UNSUPPORTED;
        }
        ++active->references;
        *provider_out = active;
        (void)pthread_mutex_unlock(&urp_image_registry_mutex);
        free(provider_bytes);
        return URP_STATUS_OK;
    }

    size_t existing_soname_count = 0U;
    /* Reject an already-loaded same-SONAME object as policy; binding correctness
     * is provided by the fresh namespace below, not by this base-namespace scan. */
    if (!urp_loaded_soname_count(adapter->provider_soname, &existing_soname_count)
        || existing_soname_count != 0U) {
        (void)pthread_mutex_unlock(&urp_image_registry_mutex);
        free(provider_bytes);
        return URP_STATUS_UNSUPPORTED;
    }

    int provider_fd = urp_create_sealed_memfd(
        "urprotect-trusted-provider", provider_bytes, provider_size,
        S_IRUSR | S_IXUSR);
    free(provider_bytes);
    if (provider_fd < 0) {
        (void)pthread_mutex_unlock(&urp_image_registry_mutex);
        return URP_STATUS_LOAD_FAILED;
    }
    char fd_path[64];
    int path_size = snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", provider_fd);
    if (path_size < 0 || (size_t)path_size >= sizeof(fd_path)) {
        (void)close(provider_fd);
        (void)pthread_mutex_unlock(&urp_image_registry_mutex);
        return URP_STATUS_LOAD_FAILED;
    }
    (void)dlerror();
#if defined(URP_HOST_ADAPTER_TEST_DIAGNOSTICS)
    (void)atomic_fetch_add_explicit(&urp_loader_attempt_count, 1U, memory_order_relaxed);
#endif
    void *provider_handle = dlmopen(LM_ID_NEWLM, fd_path, RTLD_NOW | RTLD_LOCAL);
    if (provider_handle == NULL) {
        (void)close(provider_fd);
        (void)pthread_mutex_unlock(&urp_image_registry_mutex);
        return URP_STATUS_LOAD_FAILED;
    }
    uintptr_t table_address = 0U;
    Lmid_t namespace_id = LM_ID_BASE;
    struct link_map *provider_map = NULL;
    int valid_provider = urp_provider_runtime_image_valid(
        provider_fd, provider_handle, &facts, &table_address, &namespace_id, &provider_map);
    if (!valid_provider) {
        (void)dlclose(provider_handle);
        (void)close(provider_fd);
        (void)pthread_mutex_unlock(&urp_image_registry_mutex);
        return URP_STATUS_UNSUPPORTED;
    }

    urp_loaded_provider *provider = (urp_loaded_provider *)calloc(1U, sizeof(*provider));
    if (provider == NULL) {
        (void)dlclose(provider_handle);
        (void)close(provider_fd);
        (void)pthread_mutex_unlock(&urp_image_registry_mutex);
        return URP_STATUS_LOAD_FAILED;
    }
    provider->dl_handle = provider_handle;
    provider->fd = provider_fd;
    provider->namespace_id = namespace_id;
    provider->link_map = provider_map;
    provider->references = 1U;
    provider->table_address = table_address;
    memcpy(provider->soname, adapter->provider_soname, sizeof(provider->soname));
    memcpy(provider->build_id_hex, adapter->provider_build_id_hex, sizeof(provider->build_id_hex));
    memcpy(provider->sha256_hex, adapter->provider_sha256_hex, sizeof(provider->sha256_hex));
    memcpy(provider->table_bytes, facts.table_bytes, sizeof(provider->table_bytes));
    urp_active_provider = provider;
    *provider_out = provider;
    (void)pthread_mutex_unlock(&urp_image_registry_mutex);
    return URP_STATUS_OK;
}

static urp_status urp_release_provider(urp_loaded_provider *provider)
{
    if (provider == NULL) return URP_STATUS_OK;
    (void)pthread_mutex_lock(&urp_image_registry_mutex);
    if (provider != urp_active_provider || provider->references == 0U) {
        (void)pthread_mutex_unlock(&urp_image_registry_mutex);
        return URP_STATUS_LOAD_FAILED;
    }
    --provider->references;
    if (provider->references != 0U) {
        (void)pthread_mutex_unlock(&urp_image_registry_mutex);
        return URP_STATUS_OK;
    }
    if (dlclose(provider->dl_handle) != 0) {
        /* A failed unload remains pinned rather than invalidating a live mapping. */
        (void)pthread_mutex_unlock(&urp_image_registry_mutex);
        return URP_STATUS_LOAD_FAILED;
    }
    int close_status = close(provider->fd);
    urp_active_provider = NULL;
    free(provider);
    (void)pthread_mutex_unlock(&urp_image_registry_mutex);
    return close_status == 0 ? URP_STATUS_OK : URP_STATUS_LOAD_FAILED;
}

static int urp_verify_provider_consumer_binding(
    void *consumer_handle,
    uint64_t got_virtual_address,
    const urp_loaded_provider *provider)
{
    struct link_map *consumer_map = NULL;
    Lmid_t consumer_namespace = LM_ID_BASE;
    if (consumer_handle == NULL || provider == NULL || provider->link_map == NULL
        || dlinfo(consumer_handle, RTLD_DI_LMID, &consumer_namespace) != 0
        || consumer_namespace != provider->namespace_id
        || dlinfo(consumer_handle, RTLD_DI_LINKMAP, &consumer_map) != 0
        || consumer_map == NULL || got_virtual_address > (uint64_t)UINTPTR_MAX
        || (uintptr_t)consumer_map->l_addr > UINTPTR_MAX - (uintptr_t)got_virtual_address) {
        return 0;
    }
    uintptr_t slot_address = (uintptr_t)consumer_map->l_addr + (uintptr_t)got_virtual_address;
    uintptr_t slot_value = 0U;
    memcpy(&slot_value, (const void *)slot_address, sizeof(slot_value));
    (void)dlerror();
    void *symbol = dlsym(consumer_handle, URP_HOST_EXTERNAL_TABLE_SYMBOL);
    struct link_map *symbol_map = NULL;
    Dl_info symbol_info;
    return symbol != NULL && dlerror() == NULL
        && dladdr1(symbol, &symbol_info, (void **)&symbol_map, RTLD_DL_LINKMAP) != 0
        && symbol_map == provider->link_map
        && (uintptr_t)symbol == provider->table_address
        && slot_value == provider->table_address
        && memcmp((const void *)provider->table_address, provider->table_bytes,
            sizeof(provider->table_bytes)) == 0;
}
#endif

static urp_status urp_adapter_load_image(
    void *userdata,
    const void *bytes,
    size_t size,
    uint32_t flags,
    urp_image_handle *out_handle)
{
    urp_host_adapter_v1 *adapter = (urp_host_adapter_v1 *)userdata;
    if (out_handle == NULL) {
        return URP_STATUS_INVALID_ARGUMENT;
    }
    *out_handle = 0U;
    if (adapter == NULL || bytes == NULL || size == 0U
        || (flags & URP_LOAD_IMAGE_IMMUTABLE) == 0U) {
        return URP_STATUS_INVALID_ARGUMENT;
    }

    size_t dependency_count = 0U;
    int uses_provider = 0;
    uint64_t provider_got_virtual_address = 0U;
    const char *expected_provider_soname = adapter->provider_configured != 0U
        ? adapter->provider_soname : NULL;
    urp_status validation = urp_host_image_validate_with_provider(
        bytes, size, expected_provider_soname, &dependency_count,
        &uses_provider, &provider_got_virtual_address);
    if (validation != URP_STATUS_OK) return validation;

    urp_loaded_provider *provider = NULL;
    if (uses_provider) {
#if defined(__GLIBC__)
        urp_status provider_status = urp_acquire_provider(adapter, &provider);
        if (provider_status != URP_STATUS_OK) return provider_status;
#else
        return URP_STATUS_UNSUPPORTED;
#endif
    }
    if (dependency_count == 2U) {
        static const char *const loader_variables[] = {
            "LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT"
        };
        for (size_t index = 0U;
             index < sizeof(loader_variables) / sizeof(loader_variables[0]);
             ++index) {
            const char *value = getenv(loader_variables[index]);
            if (value != NULL && value[0] != '\0') {
#if defined(__GLIBC__)
                (void)urp_release_provider(provider);
#endif
                return URP_STATUS_UNSUPPORTED;
            }
        }
    }

    int fd = urp_create_sealed_memfd(
        "urprotect-host-image", bytes, size,
        S_IRUSR | S_IWUSR | S_IXUSR);
    if (fd < 0) {
#if defined(__GLIBC__)
        (void)urp_release_provider(provider);
#endif
        return URP_STATUS_LOAD_FAILED;
    }
    char fd_path[64];
    int path_size = snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    if (path_size < 0 || (size_t)path_size >= sizeof(fd_path)) {
        (void)close(fd);
#if defined(__GLIBC__)
        (void)urp_release_provider(provider);
#endif
        return URP_STATUS_LOAD_FAILED;
    }

    (void)dlerror();
#if defined(URP_HOST_ADAPTER_TEST_DIAGNOSTICS)
    (void)atomic_fetch_add_explicit(&urp_loader_attempt_count, 1U, memory_order_relaxed);
#endif
#if defined(__GLIBC__)
    void *dl_handle = uses_provider
        ? dlmopen(provider->namespace_id, fd_path, RTLD_NOW | RTLD_LOCAL)
        : dlopen(fd_path, RTLD_NOW | RTLD_LOCAL);
#else
    void *dl_handle = dlopen(fd_path, RTLD_NOW | RTLD_LOCAL);
#endif
    if (dl_handle == NULL) {
#if defined(URP_HOST_ADAPTER_TEST_DIAGNOSTICS)
        const char *loader_error = dlerror();
        (void)fprintf(stderr, "HostContext adapter dlopen failed: %s\n",
            loader_error != NULL ? loader_error : "unknown loader error");
#endif
        (void)close(fd);
#if defined(__GLIBC__)
        (void)urp_release_provider(provider);
#endif
        return URP_STATUS_LOAD_FAILED;
    }
#if defined(__GLIBC__)
    if (uses_provider
        && !urp_verify_provider_consumer_binding(
            dl_handle, provider_got_virtual_address, provider)) {
        (void)dlclose(dl_handle);
        (void)close(fd);
        (void)urp_release_provider(provider);
        return URP_STATUS_UNSUPPORTED;
    }
#endif

    urp_fd_image *image = (urp_fd_image *)calloc(1U, sizeof(*image));
    if (image == NULL) {
        (void)dlclose(dl_handle);
        (void)close(fd);
#if defined(__GLIBC__)
        (void)urp_release_provider(provider);
#endif
        return URP_STATUS_LOAD_FAILED;
    }
    image->dl_handle = dl_handle;
    image->fd = fd;
    image->provider = provider;
    image->owner = pthread_self();
    (void)pthread_mutex_lock(&urp_image_registry_mutex);
    if (urp_next_image_handle == 0U || urp_next_image_handle == UINT64_MAX) {
        (void)pthread_mutex_unlock(&urp_image_registry_mutex);
        (void)dlclose(dl_handle);
        (void)close(fd);
#if defined(__GLIBC__)
        (void)urp_release_provider(provider);
#endif
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
    urp_status provider_release_status = URP_STATUS_OK;
#if defined(__GLIBC__)
    if (image->provider != NULL) {
        provider_release_status = urp_release_provider(image->provider);
    }
#endif
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
    return close_result == 0 && provider_release_status == URP_STATUS_OK
        ? URP_STATUS_OK : URP_STATUS_LOAD_FAILED;
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

size_t urp_host_adapter_loader_attempts(void)
{
    return atomic_load_explicit(&urp_loader_attempt_count, memory_order_relaxed);
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

static void urp_host_adapter_initialize_context(urp_host_adapter_v1 *adapter)
{
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

void urp_host_adapter_init(urp_host_adapter_v1 *adapter)
{
    if (adapter == NULL) return;
    memset(adapter, 0, sizeof(*adapter));
    urp_host_adapter_initialize_context(adapter);
}

static int urp_copy_config_string(char *destination, size_t capacity, const char *source)
{
    if (destination == NULL || capacity == 0U || source == NULL) return 0;
    size_t length = strnlen(source, capacity);
    if (length == 0U || length >= capacity) return 0;
    memcpy(destination, source, length + 1U);
    return 1;
}

urp_status urp_host_adapter_init_with_provider(
    urp_host_adapter_v1 *adapter,
    const urp_host_provider_config_v1 *provider)
{
    if (adapter == NULL) return URP_STATUS_INVALID_ARGUMENT;
    urp_host_adapter_init(adapter);
    if (provider == NULL || provider->path == NULL || provider->path[0] != '/'
        || provider->expected_soname == NULL
        || strcmp(provider->expected_soname, URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME) != 0
        || !urp_is_hex_string(provider->expected_build_id_hex, 40U)
        || !urp_is_hex_string(provider->expected_sha256_hex, 64U)
        || !urp_copy_config_string(adapter->provider_path, sizeof(adapter->provider_path), provider->path)
        || !urp_copy_config_string(adapter->provider_soname, sizeof(adapter->provider_soname), provider->expected_soname)
        || !urp_copy_config_string(adapter->provider_build_id_hex, sizeof(adapter->provider_build_id_hex), provider->expected_build_id_hex)
        || !urp_copy_config_string(adapter->provider_sha256_hex, sizeof(adapter->provider_sha256_hex), provider->expected_sha256_hex)) {
        return URP_STATUS_INVALID_ARGUMENT;
    }
    adapter->provider_configured = 1U;
    return URP_STATUS_OK;
}
