#define _GNU_SOURCE

#include "native_process_identity.h"

#include "../urprotect-launcher/sha256.h"

#include <errno.h>
#include <elf.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__GLIBC__)
#include <gnu/libc-version.h>
#endif

#define MAX_MAPS_BYTES (1024U * 1024U)
#define MAX_MAP_LINE_BYTES 8192U
#define MAX_RUNTIME_FILE_BYTES (32U * 1024U * 1024U)
#define MAX_IDENTITY_TOTAL_BYTES (96U * 1024U * 1024U)
#define MAX_IDENTITY_JSON_BYTES 16384U
#define IDENTITY_PATH_CAPACITY 4096U
#define IDENTITY_RELPATH_CAPACITY 512U

typedef struct {
    char path[IDENTITY_PATH_CAPACITY];
    uint32_t device_major;
    uint32_t device_minor;
    uint64_t inode;
    uint64_t map_start;
    uint64_t map_end;
    uint64_t file_offset;
    char permissions[5];
    int present;
} mapped_file;

typedef struct {
    uint64_t file_offset;
    uint64_t virtual_address;
    uint64_t file_size;
    uint64_t memory_size;
    uint32_t flags;
} load_segment;

typedef struct {
    load_segment segments[4096];
    size_t segment_count;
    char interpreter[IDENTITY_PATH_CAPACITY];
    uint16_t type;
    uint16_t machine;
} elf_identity;

typedef struct {
    char mapped_path[IDENTITY_PATH_CAPACITY];
    char retained_path[IDENTITY_RELPATH_CAPACITY];
    uint32_t device_major;
    uint32_t device_minor;
    uint64_t inode;
    uint64_t size;
    char sha256[65];
} captured_file;

typedef struct {
    uint64_t start;
    uint64_t end;
} virtual_page_range;

static void digest_hex(const uint8_t *bytes, size_t size, char output[65])
{
    uint8_t digest[32];
    static const char hex[] = "0123456789abcdef";
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

static int is_sha256(const char *value)
{
    if (value == NULL || strlen(value) != 64U) return 0;
    for (size_t index = 0U; index < 64U; ++index) {
        char ch = value[index];
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return 0;
    }
    return 1;
}

static int is_safe_relative_directory(const char *value)
{
    size_t length;
    if (value == NULL) return 0;
    length = strlen(value);
    if (length == 0U || length >= IDENTITY_RELPATH_CAPACITY
        || value[0] == '/' || value[length - 1U] == '/') return 0;
    for (size_t index = 0U; index < length; ++index) {
        unsigned char ch = (unsigned char)value[index];
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
              || (ch >= '0' && ch <= '9') || ch == '/' || ch == '.'
              || ch == '_' || ch == '-')) return 0;
        if (ch == '/' && (index == 0U || value[index - 1U] == '/')) return 0;
    }
    if (strstr(value, "..") != NULL) return 0;
    return 1;
}

static int safe_mapped_path(const char *path)
{
    if (path == NULL || path[0] != '/') return 0;
    for (const unsigned char *cursor = (const unsigned char *)path; *cursor != 0U; ++cursor) {
        if (*cursor < 0x20U || *cursor > 0x7eU || *cursor == '\\' || *cursor == '"') return 0;
    }
    return strstr(path, " (deleted)") == NULL;
}

static int same_stat_identity(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev
        && left->st_ino == right->st_ino
        && left->st_size == right->st_size
        && left->st_mtim.tv_sec == right->st_mtim.tv_sec
        && left->st_mtim.tv_nsec == right->st_mtim.tv_nsec
        && left->st_ctim.tv_sec == right->st_ctim.tv_sec
        && left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
}

static int read_bounded_file(const char *path, size_t maximum, uint8_t **bytes_out, size_t *size_out)
{
    int fd = -1;
    uint8_t *bytes = NULL;
    size_t used = 0U;
    if (path == NULL || bytes_out == NULL || size_out == NULL) return 0;
    *bytes_out = NULL;
    *size_out = 0U;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 0;
    bytes = (uint8_t *)malloc(maximum + 1U);
    if (bytes == NULL) {
        (void)close(fd);
        return 0;
    }
    while (used < maximum + 1U) {
        size_t request = maximum + 1U - used;
        ssize_t count = read(fd, bytes + used, request);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            free(bytes);
            (void)close(fd);
            return 0;
        }
        if (count == 0) break;
        used += (size_t)count;
    }
    (void)close(fd);
    if (used == 0U || used > maximum) {
        free(bytes);
        return 0;
    }
    *bytes_out = bytes;
    *size_out = used;
    return 1;
}

static int parse_map_line(const char *line, mapped_file *result)
{
    unsigned long long start;
    unsigned long long end;
    unsigned long long file_offset;
    unsigned long long inode;
    unsigned int device_major;
    unsigned int device_minor;
    char permissions[5] = {0};
    int consumed = 0;
    int parsed;
    const char *path;
    size_t length;
    if (line == NULL || result == NULL) return 0;
    parsed = sscanf(
        line,
        "%llx-%llx %4s %llx %x:%x %llu%n",
        &start,
        &end,
        permissions,
        &file_offset,
        &device_major,
        &device_minor,
        &inode,
        &consumed);
    if (parsed != 7 || consumed <= 0 || start >= end) return 0;
    path = line + (size_t)consumed;
    while (*path == ' ' || *path == '\t') ++path;
    if (*path == '\0' || *path == '\n') return 1;
    length = strcspn(path, "\r\n");
    if (length == 0U || length >= sizeof(result->path)) return 0;
    memcpy(result->path, path, length);
    result->path[length] = '\0';
    result->device_major = (uint32_t)device_major;
    result->device_minor = (uint32_t)device_minor;
    result->inode = (uint64_t)inode;
    result->map_start = (uint64_t)start;
    result->map_end = (uint64_t)end;
    result->file_offset = (uint64_t)file_offset;
    if (strlen(permissions) != 4U
        || (permissions[0] != 'r' && permissions[0] != '-')
        || (permissions[1] != 'w' && permissions[1] != '-')
        || (permissions[2] != 'x' && permissions[2] != '-')
        || (permissions[3] != 'p' && permissions[3] != 's')) return 0;
    (void)snprintf(result->permissions, sizeof(result->permissions), "%s", permissions);
    result->present = 1;
    return 1;
}

static int same_mapping(const mapped_file *left, const mapped_file *right)
{
    return left->device_major == right->device_major
        && left->device_minor == right->device_minor
        && left->inode == right->inode
        && strcmp(left->path, right->path) == 0;
}

static int add_unique_mapping(mapped_file *slot, const mapped_file *candidate)
{
    if (slot == NULL || candidate == NULL || !candidate->present || !safe_mapped_path(candidate->path)) return 0;
    if (!slot->present) {
        *slot = *candidate;
        return 1;
    }
    return same_mapping(slot, candidate);
}

static const char *base_name(const char *path)
{
    const char *slash;
    if (path == NULL) return "";
    slash = strrchr(path, '/');
    return slash == NULL ? path : slash + 1;
}

static uint16_t read_u16_le(const uint8_t *bytes)
{
    return (uint16_t)bytes[0] | (uint16_t)((uint16_t)bytes[1] << 8U);
}

static uint32_t read_u32_le(const uint8_t *bytes)
{
    return (uint32_t)bytes[0]
        | ((uint32_t)bytes[1] << 8U)
        | ((uint32_t)bytes[2] << 16U)
        | ((uint32_t)bytes[3] << 24U);
}

static uint64_t read_u64_le(const uint8_t *bytes)
{
    return (uint64_t)read_u32_le(bytes) | ((uint64_t)read_u32_le(bytes + 4U) << 32U);
}

static int parse_elf_identity(const uint8_t *bytes, size_t size, elf_identity *result, int require_interpreter)
{
    uint64_t phoff;
    uint16_t phentsize;
    uint16_t phnum;
    int interpreter_count = 0;
    if (bytes == NULL || result == NULL || size < 64U
        || memcmp(bytes, ELFMAG, SELFMAG) != 0
        || bytes[EI_CLASS] != ELFCLASS64
        || bytes[EI_DATA] != ELFDATA2LSB
        || bytes[EI_VERSION] != EV_CURRENT
        || read_u32_le(bytes + 20U) != EV_CURRENT) return 0;
    memset(result, 0, sizeof(*result));
    result->type = read_u16_le(bytes + 16U);
    result->machine = read_u16_le(bytes + 18U);
    phoff = read_u64_le(bytes + 32U);
    phentsize = read_u16_le(bytes + 54U);
    phnum = read_u16_le(bytes + 56U);
    if (result->machine != EM_AARCH64
        || (result->type != ET_DYN && result->type != ET_EXEC)
        || phentsize < 56U || phnum == 0U || phnum > 4096U
        || phoff > (uint64_t)size
        || (uint64_t)phnum > ((uint64_t)size - phoff) / (uint64_t)phentsize) return 0;
    for (uint16_t index = 0U; index < phnum; ++index) {
        const uint8_t *header = bytes + (size_t)phoff + (size_t)index * (size_t)phentsize;
        uint32_t type = read_u32_le(header);
        uint32_t flags = read_u32_le(header + 4U);
        uint64_t offset = read_u64_le(header + 8U);
        uint64_t file_size = read_u64_le(header + 32U);
        uint64_t memory_size = read_u64_le(header + 40U);
        uint64_t virtual_address = read_u64_le(header + 16U);
        if (type == PT_LOAD) {
            if (result->segment_count >= sizeof(result->segments) / sizeof(result->segments[0])
                || file_size > memory_size || offset > (uint64_t)size || file_size > (uint64_t)size - offset
                || virtual_address > UINT64_MAX - memory_size) return 0;
            result->segments[result->segment_count].file_offset = offset;
            result->segments[result->segment_count].virtual_address = virtual_address;
            result->segments[result->segment_count].file_size = file_size;
            result->segments[result->segment_count].memory_size = memory_size;
            result->segments[result->segment_count].flags = flags;
            ++result->segment_count;
        } else if (type == PT_INTERP) {
            size_t interp_length;
            if (++interpreter_count != 1 || file_size < 2U || file_size > IDENTITY_PATH_CAPACITY
                || offset > (uint64_t)size || file_size > (uint64_t)size - offset) return 0;
            interp_length = (size_t)file_size;
            if (bytes[(size_t)offset + interp_length - 1U] != 0U
                || memchr(bytes + (size_t)offset, 0, interp_length - 1U) != NULL) return 0;
            if (interp_length >= sizeof(result->interpreter)) return 0;
            memcpy(result->interpreter, bytes + (size_t)offset, interp_length - 1U);
            if (result->interpreter[0] != '/') return 0;
            for (size_t character = 0U; character < interp_length - 1U; ++character) {
                unsigned char value = (unsigned char)result->interpreter[character];
                if (value < 0x20U || value > 0x7eU || value == (unsigned char)'\\') return 0;
            }
        }
    }
    if (result->segment_count == 0U || (require_interpreter && interpreter_count != 1)) return 0;
    return 1;
}

static int find_mapping_by_stat(const uint8_t *maps, size_t maps_size, const struct stat *metadata, mapped_file *result)
{
    size_t offset = 0U;
    char line[MAX_MAP_LINE_BYTES];
    mapped_file found = {0};
    uint32_t device_major = (uint32_t)major(metadata->st_dev);
    uint32_t device_minor = (uint32_t)minor(metadata->st_dev);
    uint64_t inode = (uint64_t)metadata->st_ino;
    while (offset < maps_size) {
        size_t end = offset;
        size_t length;
        mapped_file candidate = {0};
        while (end < maps_size && maps[end] != (uint8_t)'\n') ++end;
        length = end - offset;
        if (length == 0U || length >= sizeof(line)) return 0;
        memcpy(line, maps + offset, length);
        line[length] = '\0';
        if (!parse_map_line(line, &candidate)) return 0;
        if (candidate.present && candidate.device_major == device_major
            && candidate.device_minor == device_minor && candidate.inode == inode) {
            if (!add_unique_mapping(&found, &candidate)) return 0;
        }
        offset = end < maps_size ? end + 1U : end;
    }
    if (!found.present) return 0;
    *result = found;
    return 1;
}

static int find_glibc_libc_mapping(const uint8_t *maps, size_t maps_size, mapped_file *result)
{
    size_t offset = 0U;
    char line[MAX_MAP_LINE_BYTES];
    mapped_file found = {0};
    while (offset < maps_size) {
        size_t end = offset;
        size_t length;
        mapped_file candidate = {0};
        while (end < maps_size && maps[end] != (uint8_t)'\n') ++end;
        length = end - offset;
        if (length == 0U || length >= sizeof(line)) return 0;
        memcpy(line, maps + offset, length);
        line[length] = '\0';
        if (!parse_map_line(line, &candidate)) return 0;
        if (candidate.present && strcmp(base_name(candidate.path), "libc.so.6") == 0) {
            if (!add_unique_mapping(&found, &candidate)) return 0;
        }
        offset = end < maps_size ? end + 1U : end;
    }
    if (!found.present) return 0;
    *result = found;
    return 1;
}

static int checked_add_u64(uint64_t left, uint64_t right, uint64_t *result)
{
    if (result == NULL || left > UINT64_MAX - right) return 0;
    *result = left + right;
    return 1;
}

static int checked_align_up_u64(uint64_t value, uint64_t alignment, uint64_t *result)
{
    uint64_t adjustment;
    if (result == NULL || alignment == 0U || (alignment & (alignment - 1U)) != 0U) return 0;
    adjustment = alignment - 1U;
    if (value > UINT64_MAX - adjustment) return 0;
    *result = (value + adjustment) & ~adjustment;
    return 1;
}

static int intervals_intersect(uint64_t left_start, uint64_t left_end, uint64_t right_start, uint64_t right_end)
{
    return left_start < right_end && right_start < left_end;
}

static int segment_memory_page_range(
    const load_segment *segment,
    uint64_t page_size,
    virtual_page_range *result)
{
    uint64_t memory_end;
    if (segment == NULL || result == NULL || page_size == 0U
        || (page_size & (page_size - 1U)) != 0U) return 0;
    result->start = segment->virtual_address & ~(page_size - 1U);
    if (segment->memory_size == 0U) {
        result->end = result->start;
        return 1;
    }
    if (!checked_add_u64(segment->virtual_address, segment->memory_size, &memory_end)
        || !checked_align_up_u64(memory_end, page_size, &result->end)) return 0;
    return result->end > result->start;
}

static int find_file_backed_mapping_owner(
    const mapped_file *mapping,
    const elf_identity *elf,
    uint64_t page_size,
    uint64_t file_page_limit,
    uint32_t map_flags,
    int load_bias_known,
    uint64_t load_bias,
    size_t *owner_index_out,
    uint64_t *load_bias_out)
{
    uint64_t mapping_size;
    uint64_t map_file_end;
    size_t owner_count = 0U;
    size_t owner_index = 0U;
    uint64_t owner_bias = 0U;
    if (mapping == NULL || elf == NULL || owner_index_out == NULL || load_bias_out == NULL
        || mapping->map_start >= mapping->map_end) return 0;
    mapping_size = mapping->map_end - mapping->map_start;
    if (!checked_add_u64(mapping->file_offset, mapping_size, &map_file_end)
        || map_file_end > file_page_limit) return 0;
    for (size_t index = 0U; index < elf->segment_count; ++index) {
        const load_segment *segment = &elf->segments[index];
        uint64_t file_page_start;
        uint64_t virtual_page_start;
        uint64_t segment_file_end;
        uint64_t file_page_end;
        uint64_t delta;
        uint64_t expected_vaddr;
        uint64_t candidate_bias;
        if (segment->file_size == 0U) continue;
        file_page_start = segment->file_offset & ~(page_size - 1U);
        virtual_page_start = segment->virtual_address & ~(page_size - 1U);
        if (!checked_add_u64(segment->file_offset, segment->file_size, &segment_file_end)
            || !checked_align_up_u64(segment_file_end, page_size, &file_page_end)) return 0;
        if (!intervals_intersect(mapping->file_offset, map_file_end, file_page_start, file_page_end)) continue;
        /* A PT_LOAD can reuse a rounded file page at a distinct VA. Such an
         * intersection is not an owner; the complete VMA must be contained by
         * one candidate, and its VA/memsz owner is checked independently. */
        if (mapping->file_offset < file_page_start || map_file_end > file_page_end) continue;
        if ((map_flags & ~segment->flags) != 0U) return 0;
        delta = mapping->file_offset - file_page_start;
        if (!checked_add_u64(virtual_page_start, delta, &expected_vaddr)) return 0;
        if (load_bias_known) {
            if (!checked_add_u64(load_bias, expected_vaddr, &expected_vaddr)
                || mapping->map_start != expected_vaddr) return 0;
            candidate_bias = load_bias;
        } else {
            if (mapping->map_start < expected_vaddr) return 0;
            candidate_bias = mapping->map_start - expected_vaddr;
        }
        if (owner_count != 0U && candidate_bias != owner_bias) return 0;
        owner_bias = candidate_bias;
        owner_index = index;
        ++owner_count;
    }
    if (owner_count != 1U) return 0;
    *owner_index_out = owner_index;
    *load_bias_out = owner_bias;
    return 1;
}

static int verify_unique_virtual_memory_owner(
    const elf_identity *elf,
    uint64_t page_size,
    uint64_t load_bias,
    uint64_t map_start,
    uint64_t map_end,
    size_t file_owner_index)
{
    uint64_t virtual_start;
    uint64_t virtual_end;
    size_t owner_count = 0U;
    size_t owner_index = 0U;
    if (elf == NULL || map_start >= map_end || map_start < load_bias || map_end < load_bias) return 0;
    virtual_start = map_start - load_bias;
    virtual_end = map_end - load_bias;
    if (virtual_start >= virtual_end) return 0;
    for (size_t index = 0U; index < elf->segment_count; ++index) {
        virtual_page_range memory_range;
        if (!segment_memory_page_range(&elf->segments[index], page_size, &memory_range)) return 0;
        if (memory_range.start == memory_range.end
            || !intervals_intersect(virtual_start, virtual_end, memory_range.start, memory_range.end)) continue;
        if (virtual_start < memory_range.start || virtual_end > memory_range.end) return 0;
        if (index != file_owner_index) return 0;
        owner_index = index;
        ++owner_count;
    }
    return owner_count == 1U && owner_index == file_owner_index;
}

static int compare_virtual_page_ranges(const void *left, const void *right)
{
    const virtual_page_range *left_range = (const virtual_page_range *)left;
    const virtual_page_range *right_range = (const virtual_page_range *)right;
    if (left_range->start < right_range->start) return -1;
    if (left_range->start > right_range->start) return 1;
    if (left_range->end < right_range->end) return -1;
    if (left_range->end > right_range->end) return 1;
    return 0;
}

static int verify_maps_against_elf(
    const uint8_t *maps,
    size_t maps_size,
    const mapped_file *identity,
    const uint8_t *elf_bytes,
    size_t elf_size,
    int require_executable_mapping)
{
    elf_identity elf;
    size_t offset = 0U;
    char line[MAX_MAP_LINE_BYTES];
    size_t matching_rows = 0U;
    int have_load_bias = 0;
    int executable_mapping = 0;
    uint64_t load_bias = 0U;
    long page_size_long = sysconf(_SC_PAGESIZE);
    uint64_t page_size;
    uint64_t file_page_limit;
    if (page_size_long <= 0) return 0;
    page_size = (uint64_t)page_size_long;
    if ((page_size & (page_size - 1U)) != 0U
        || !parse_elf_identity(elf_bytes, elf_size, &elf, 0)
        || (uint64_t)elf_size > UINT64_MAX - (page_size - 1U)) return 0;
    file_page_limit = ((uint64_t)elf_size + page_size - 1U) & ~(page_size - 1U);

    /* Establish the ELF load bias from executable file-backed mappings. */
    while (offset < maps_size) {
        size_t end = offset;
        size_t length;
        mapped_file candidate = {0};
        while (end < maps_size && maps[end] != (uint8_t)'\n') ++end;
        length = end - offset;
        if (length == 0U || length >= sizeof(line)) return 0;
        memcpy(line, maps + offset, length);
        line[length] = '\0';
        if (!parse_map_line(line, &candidate)) return 0;
        if (candidate.present && candidate.device_major == identity->device_major
            && candidate.device_minor == identity->device_minor && candidate.inode == identity->inode) {
            if (strcmp(candidate.path, identity->path) != 0
                || candidate.map_end - candidate.map_start > UINT64_MAX - candidate.file_offset) return 0;
            if (candidate.permissions[2] == 'x') {
                uint32_t map_flags = 0U;
                size_t owner_index = 0U;
                uint64_t candidate_bias = 0U;
                if (candidate.permissions[0] == 'r') map_flags |= PF_R;
                if (candidate.permissions[1] == 'w') map_flags |= PF_W;
                map_flags |= PF_X;
                if (!find_file_backed_mapping_owner(
                        &candidate,
                        &elf,
                        page_size,
                        file_page_limit,
                        map_flags,
                        0,
                        0U,
                        &owner_index,
                        &candidate_bias)
                    || (elf.segments[owner_index].flags & PF_X) == 0U
                    || !verify_unique_virtual_memory_owner(
                        &elf,
                        page_size,
                        candidate_bias,
                        candidate.map_start,
                        candidate.map_end,
                        owner_index)) return 0;
                if (have_load_bias && candidate_bias != load_bias) return 0;
                load_bias = candidate_bias;
                have_load_bias = 1;
                executable_mapping = 1;
            }
        } else if (candidate.present && strcmp(candidate.path, identity->path) == 0) {
            return 0;
        }
        offset = end < maps_size ? end + 1U : end;
    }
    if (!have_load_bias || (require_executable_mapping && !executable_mapping)) return 0;

    offset = 0U;
    while (offset < maps_size) {
        size_t end = offset;
        size_t length;
        mapped_file candidate = {0};
        uint64_t map_size;
        int mapped = 0;
        uint32_t map_flags = 0U;
        while (end < maps_size && maps[end] != (uint8_t)'\n') ++end;
        length = end - offset;
        if (length == 0U || length >= sizeof(line)) return 0;
        memcpy(line, maps + offset, length);
        line[length] = '\0';
        if (!parse_map_line(line, &candidate)) return 0;
        if (candidate.present && candidate.device_major == identity->device_major
            && candidate.device_minor == identity->device_minor && candidate.inode == identity->inode) {
            if (strcmp(candidate.path, identity->path) != 0
                || candidate.map_end - candidate.map_start > UINT64_MAX - candidate.file_offset
                || candidate.map_start < load_bias) return 0;
            ++matching_rows;
            map_size = candidate.map_end - candidate.map_start;
            if (candidate.permissions[0] == 'r') map_flags |= PF_R;
            if (candidate.permissions[1] == 'w') map_flags |= PF_W;
            if (candidate.permissions[2] == 'x') map_flags |= PF_X;
            if (map_flags != 0U) {
                size_t owner_index = 0U;
                uint64_t checked_load_bias = 0U;
                if (!find_file_backed_mapping_owner(
                        &candidate,
                        &elf,
                        page_size,
                        file_page_limit,
                        map_flags,
                        1,
                        load_bias,
                        &owner_index,
                        &checked_load_bias)
                    || checked_load_bias != load_bias
                    || !verify_unique_virtual_memory_owner(
                        &elf,
                        page_size,
                        load_bias,
                        candidate.map_start,
                        candidate.map_end,
                        owner_index)) return 0;
                mapped = 1;
            }
            if (!mapped && map_flags == 0U
                && candidate.file_offset <= file_page_limit
                && map_size <= MAX_RUNTIME_FILE_BYTES) {
                virtual_page_range memory_ranges[4096];
                size_t memory_range_count = 0U;
                size_t merged_range_count = 0U;
                size_t gap_count = 0U;
                for (size_t index = 0U; index < elf.segment_count; ++index) {
                    virtual_page_range memory_range;
                    if (!segment_memory_page_range(&elf.segments[index], page_size, &memory_range)) return 0;
                    if (memory_range.start == memory_range.end) continue;
                    if (memory_range_count >= sizeof(memory_ranges) / sizeof(memory_ranges[0])) return 0;
                    memory_ranges[memory_range_count] = memory_range;
                    ++memory_range_count;
                }
                qsort(memory_ranges, memory_range_count, sizeof(memory_ranges[0]), compare_virtual_page_ranges);
                for (size_t index = 0U; index < memory_range_count; ++index) {
                    if (merged_range_count == 0U
                        || memory_ranges[index].start > memory_ranges[merged_range_count - 1U].end) {
                        memory_ranges[merged_range_count] = memory_ranges[index];
                        ++merged_range_count;
                    } else if (memory_ranges[index].end > memory_ranges[merged_range_count - 1U].end) {
                        memory_ranges[merged_range_count - 1U].end = memory_ranges[index].end;
                    }
                }
                for (size_t index = 0U; index + 1U < merged_range_count; ++index) {
                    uint64_t gap_start;
                    uint64_t gap_end;
                    if (memory_ranges[index].end >= memory_ranges[index + 1U].start
                        || !checked_add_u64(load_bias, memory_ranges[index].end, &gap_start)
                        || !checked_add_u64(load_bias, memory_ranges[index + 1U].start, &gap_end)) return 0;
                    if (!intervals_intersect(candidate.map_start, candidate.map_end, gap_start, gap_end)) continue;
                    if (candidate.map_start < gap_start || candidate.map_end > gap_end || ++gap_count != 1U) return 0;
                }
                mapped = gap_count == 1U;
            }
            if (!mapped) return 0;
            if (candidate.permissions[2] == 'x') executable_mapping = 1;
        } else if (candidate.present && strcmp(candidate.path, identity->path) == 0) {
            return 0;
        }
        offset = end < maps_size ? end + 1U : end;
    }
    return matching_rows != 0U && (!require_executable_mapping || executable_mapping);
}

#ifdef URP_NATIVE_PROCESS_IDENTITY_TEST
int urp_native_process_identity_test_verify_maps(
    const uint8_t *maps,
    size_t maps_size,
    const char *mapped_path,
    const uint8_t *elf_bytes,
    size_t elf_size,
    int require_executable_mapping)
{
    mapped_file identity = {0};
    size_t path_length;
    if (mapped_path == NULL) return 0;
    path_length = strlen(mapped_path);
    if (path_length == 0U || path_length >= sizeof(identity.path) || !safe_mapped_path(mapped_path)) return 0;
    memcpy(identity.path, mapped_path, path_length + 1U);
    identity.device_major = 8U;
    identity.device_minor = 1U;
    identity.inode = 1001U;
    identity.present = 1;
    return verify_maps_against_elf(
        maps,
        maps_size,
        &identity,
        elf_bytes,
        elf_size,
        require_executable_mapping);
}
#endif

static int write_all(int fd, const uint8_t *bytes, size_t size)
{
    size_t offset = 0U;
    while (offset < size) {
        ssize_t count = write(fd, bytes + offset, size - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return 0;
        offset += (size_t)count;
    }
    return 1;
}

static int retain_bytes(int directory_fd, const char *name, const uint8_t *bytes, size_t size)
{
    int fd;
    int result;
    if (directory_fd < 0 || name == NULL || bytes == NULL || size == 0U) return 0;
    fd = openat(directory_fd, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return 0;
    result = write_all(fd, bytes, size) && fsync(fd) == 0;
    if (close(fd) != 0) result = 0;
    if (!result) (void)unlinkat(directory_fd, name, 0);
    return result;
}

static int capture_regular_file(
    int source_fd,
    int directory_fd,
    const char *retained_name,
    const char *relative_directory,
    const mapped_file *mapping,
    uint64_t *total_bytes,
    captured_file *captured,
    uint8_t **bytes_out)
{
    struct stat before;
    struct stat after;
    uint8_t *bytes = NULL;
    size_t size;
    size_t offset = 0U;
    char relative_path[IDENTITY_RELPATH_CAPACITY];
    if (source_fd < 0 || directory_fd < 0 || retained_name == NULL || relative_directory == NULL
        || total_bytes == NULL || captured == NULL || bytes_out == NULL
        || fstat(source_fd, &before) != 0 || !S_ISREG(before.st_mode)
        || before.st_size <= 0 || (uint64_t)before.st_size > MAX_RUNTIME_FILE_BYTES
        || (uint64_t)before.st_size > (uint64_t)SIZE_MAX
        || (uint64_t)before.st_size > MAX_IDENTITY_TOTAL_BYTES - *total_bytes) return 0;
    if (mapping != NULL
        && ((uint32_t)major(before.st_dev) != mapping->device_major
            || (uint32_t)minor(before.st_dev) != mapping->device_minor
            || (uint64_t)before.st_ino != mapping->inode)) return 0;
    size = (size_t)before.st_size;
    bytes = (uint8_t *)malloc(size);
    if (bytes == NULL || lseek(source_fd, 0, SEEK_SET) < 0) {
        free(bytes);
        return 0;
    }
    while (offset < size) {
        ssize_t count = read(source_fd, bytes + offset, size - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            free(bytes);
            return 0;
        }
        offset += (size_t)count;
    }
    {
        uint8_t extra;
        ssize_t count;
        do {
            count = read(source_fd, &extra, sizeof(extra));
        } while (count < 0 && errno == EINTR);
        if (count != 0 || fstat(source_fd, &after) != 0 || !same_stat_identity(&before, &after)) {
            free(bytes);
            return 0;
        }
    }
    {
        int relative_path_length = snprintf(relative_path, sizeof(relative_path), "%s/%s", relative_directory, retained_name);
        if (relative_path_length < 0 || (size_t)relative_path_length >= sizeof(relative_path)) {
            free(bytes);
            return 0;
        }
    }
    if (!retain_bytes(directory_fd, retained_name, bytes, size)) {
        free(bytes);
        return 0;
    }
    if (mapping != NULL) {
        (void)snprintf(captured->mapped_path, sizeof(captured->mapped_path), "%s", mapping->path);
        captured->device_major = mapping->device_major;
        captured->device_minor = mapping->device_minor;
        captured->inode = mapping->inode;
    } else {
        captured->device_major = (uint32_t)major(before.st_dev);
        captured->device_minor = (uint32_t)minor(before.st_dev);
        captured->inode = (uint64_t)before.st_ino;
        if (captured->mapped_path[0] == '\0') {
            free(bytes);
            (void)unlinkat(directory_fd, retained_name, 0);
            return 0;
        }
    }
    captured->size = (uint64_t)size;
    (void)snprintf(captured->retained_path, sizeof(captured->retained_path), "%s", relative_path);
    digest_hex(bytes, size, captured->sha256);
    *total_bytes += (uint64_t)size;
    *bytes_out = bytes;
    return 1;
}

static int parse_version_marker(
    const uint8_t *bytes,
    size_t size,
    const char *marker,
    int patch_component_required,
    char output[64])
{
    size_t marker_length = strlen(marker);
    size_t match_start = 0U;
    size_t match_count = 0U;
    size_t version_start;
    size_t version_end;
    if (bytes == NULL || size == 0U || marker == NULL || output == NULL) return 0;
    for (size_t index = 0U; index + marker_length <= size; ++index) {
        if (memcmp(bytes + index, marker, marker_length) == 0) {
            match_start = index + marker_length;
            ++match_count;
        }
    }
    if (match_count != 1U || match_start >= size) return 0;
    version_start = match_start;
    version_end = version_start;
    while (version_end < size && version_end - version_start < 63U) {
        uint8_t ch = bytes[version_end];
        if (!((ch >= (uint8_t)'0' && ch <= (uint8_t)'9') || ch == (uint8_t)'.')) break;
        ++version_end;
    }
    if (!patch_component_required && version_end > version_start
        && bytes[version_end - 1U] == (uint8_t)'.') --version_end;
    if (version_end == version_start || version_end - version_start >= 64U) return 0;
    {
        size_t dots = 0U;
        int previous_dot = 1;
        for (size_t index = version_start; index < version_end; ++index) {
            if (bytes[index] == (uint8_t)'.') {
                if (previous_dot) return 0;
                ++dots;
                previous_dot = 1;
            } else {
                previous_dot = 0;
            }
        }
        if (previous_dot || dots != (patch_component_required ? 2U : 1U)) return 0;
    }
    memcpy(output, bytes + version_start, version_end - version_start);
    output[version_end - version_start] = '\0';
    return 1;
}

static int write_identity_json(
    int directory_fd,
    const char *relative_directory,
    const char *role,
    const char *image_sha256,
    const char *runtime,
    const char *version,
    const char *version_source,
    const char *interpreter_declared_path,
    const char *interpreter_resolved_path,
    const char *maps_relative_path,
    const char *maps_sha256,
    uint64_t *total_bytes,
    const captured_file *helper,
    const captured_file *libc,
    const captured_file *loader,
    uint8_t **identity_bytes_out,
    size_t *identity_size_out)
{
    char json[MAX_IDENTITY_JSON_BYTES];
    int length;
    if (directory_fd < 0 || relative_directory == NULL || role == NULL || image_sha256 == NULL
        || runtime == NULL || version == NULL || version_source == NULL
        || interpreter_declared_path == NULL || interpreter_resolved_path == NULL
        || maps_relative_path == NULL || maps_sha256 == NULL || total_bytes == NULL
        || helper == NULL || libc == NULL || loader == NULL
        || identity_bytes_out == NULL || identity_size_out == NULL) return 0;
    length = snprintf(
        json,
        sizeof(json),
        "{\n"
        "  \"schemaVersion\": 1,\n"
        "  \"runtime\": \"%s\",\n"
        "  \"architecture\": \"aarch64\",\n"
        "  \"role\": \"%s\",\n"
        "  \"processId\": %ld,\n"
        "  \"imageSha256\": \"%s\",\n"
        "  \"runtimeVersion\": \"%s\",\n"
        "  \"runtimeVersionSource\": \"%s\",\n"
        "  \"interpreter\": {\"declaredPath\": \"%s\", \"resolvedPath\": \"%s\", \"deviceMajor\": %" PRIu32 ", \"deviceMinor\": %" PRIu32 ", \"inode\": %" PRIu64 "},\n"
        "  \"maps\": {\"retainedPath\": \"%s\", \"sha256\": \"%s\"},\n"
        "  \"helper\": {\"mappedPath\": \"%s\", \"deviceMajor\": %" PRIu32 ", \"deviceMinor\": %" PRIu32 ", \"inode\": %" PRIu64 ", \"size\": %" PRIu64 ", \"sha256\": \"%s\", \"retainedPath\": \"%s\"},\n"
        "  \"libc\": {\"mappedPath\": \"%s\", \"deviceMajor\": %" PRIu32 ", \"deviceMinor\": %" PRIu32 ", \"inode\": %" PRIu64 ", \"size\": %" PRIu64 ", \"sha256\": \"%s\", \"retainedPath\": \"%s\"},\n"
        "  \"loader\": {\"mappedPath\": \"%s\", \"deviceMajor\": %" PRIu32 ", \"deviceMinor\": %" PRIu32 ", \"inode\": %" PRIu64 ", \"size\": %" PRIu64 ", \"sha256\": \"%s\", \"retainedPath\": \"%s\"}\n"
        "}\n",
        runtime,
        role,
        (long)getpid(),
        image_sha256,
        version,
        version_source,
        interpreter_declared_path,
        interpreter_resolved_path,
        loader->device_major,
        loader->device_minor,
        loader->inode,
        maps_relative_path,
        maps_sha256,
        helper->mapped_path,
        helper->device_major,
        helper->device_minor,
        helper->inode,
        helper->size,
        helper->sha256,
        helper->retained_path,
        libc->mapped_path,
        libc->device_major,
        libc->device_minor,
        libc->inode,
        libc->size,
        libc->sha256,
        libc->retained_path,
        loader->mapped_path,
        loader->device_major,
        loader->device_minor,
        loader->inode,
        loader->size,
        loader->sha256,
        loader->retained_path);
    if (length < 0 || (size_t)length >= sizeof(json)
        || (uint64_t)length > MAX_IDENTITY_TOTAL_BYTES - *total_bytes) return 0;
    {
        uint8_t *bytes = (uint8_t *)malloc((size_t)length);
        if (bytes == NULL) return 0;
        memcpy(bytes, json, (size_t)length);
        if (!retain_bytes(directory_fd, "identity.json", bytes, (size_t)length)) {
            free(bytes);
            return 0;
        }
        *identity_bytes_out = bytes;
        *identity_size_out = (size_t)length;
        *total_bytes += (uint64_t)length;
    }
    return 1;
}

int urp_native_process_identity_capture(
    const char *directory_path,
    const char *relative_directory,
    const char *role,
    const char *image_sha256,
    char *identity_relative_path,
    size_t identity_relative_path_capacity,
    char identity_sha256[65])
{
    int directory_fd = -1;
    int helper_fd = -1;
    int libc_fd = -1;
    int loader_fd = -1;
    uint8_t *maps = NULL;
    size_t maps_size = 0U;
    uint8_t *helper_bytes = NULL;
    uint8_t *libc_bytes = NULL;
    size_t libc_size = 0U;
    uint8_t *loader_bytes = NULL;
    uint8_t *identity_bytes = NULL;
    size_t identity_size = 0U;
    uint64_t total_bytes = 0U;
    struct stat helper_stat;
    struct stat interpreter_stat;
    mapped_file helper_mapping = {0};
    mapped_file libc_mapping = {0};
    mapped_file loader_mapping = {0};
    elf_identity helper_elf;
    elf_identity libc_elf;
    elf_identity loader_elf;
    char interpreter_resolved_path[IDENTITY_PATH_CAPACITY] = {0};
    captured_file helper_capture = {0};
    captured_file libc_capture = {0};
    captured_file loader_capture = {0};
    char runtime[16] = {0};
    char version[64] = {0};
    char version_source[64] = {0};
    char maps_relative_path[IDENTITY_RELPATH_CAPACITY];
    char libc_absolute_path[IDENTITY_PATH_CAPACITY];
    char loader_absolute_path[IDENTITY_PATH_CAPACITY];
    char relative_identity_path[IDENTITY_RELPATH_CAPACITY];
    char maps_sha256[65] = {0};
    const char *failure_stage = "identity-setup";
    int result = 0;

    if (directory_path == NULL || relative_directory == NULL || role == NULL || image_sha256 == NULL
        || identity_relative_path == NULL || identity_relative_path_capacity == 0U
        || identity_sha256 == NULL || !is_safe_relative_directory(relative_directory)
        || !is_sha256(image_sha256)
        || !(strcmp(role, "source") == 0 || strcmp(role, "target") == 0)) return 0;
    identity_relative_path[0] = '\0';
    identity_sha256[0] = '\0';
    {
        int maps_path_length = snprintf(maps_relative_path, sizeof(maps_relative_path), "%s/maps.txt", relative_directory);
        int identity_path_length = snprintf(relative_identity_path, sizeof(relative_identity_path), "%s/identity.json", relative_directory);
        if (maps_path_length < 0 || (size_t)maps_path_length >= sizeof(maps_relative_path)
            || identity_path_length < 0 || (size_t)identity_path_length >= sizeof(relative_identity_path)
            || (size_t)identity_path_length >= identity_relative_path_capacity) return 0;
    }

    failure_stage = "maps-capture";
    directory_fd = open(directory_path, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (directory_fd < 0) goto cleanup;
    if (!read_bounded_file("/proc/self/maps", MAX_MAPS_BYTES, &maps, &maps_size)) goto cleanup;
    if (maps_size > MAX_IDENTITY_TOTAL_BYTES - total_bytes) goto cleanup;
    total_bytes += (uint64_t)maps_size;
    digest_hex(maps, maps_size, maps_sha256);
    if (!retain_bytes(directory_fd, "maps.txt", maps, maps_size)) goto cleanup;

    failure_stage = "helper-map-and-snapshot";
    helper_fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (helper_fd < 0 || fstat(helper_fd, &helper_stat) != 0 || !S_ISREG(helper_stat.st_mode)
        || !find_mapping_by_stat(maps, maps_size, &helper_stat, &helper_mapping)) goto cleanup;
    (void)snprintf(helper_capture.mapped_path, sizeof(helper_capture.mapped_path), "%s", helper_mapping.path);
    if (!capture_regular_file(
            helper_fd,
            directory_fd,
            "helper.elf",
            relative_directory,
            &helper_mapping,
            &total_bytes,
            &helper_capture,
            &helper_bytes)) goto cleanup;
    failure_stage = "helper-elf-parse";
    if (!parse_elf_identity(helper_bytes, (size_t)helper_capture.size, &helper_elf, 1)) goto cleanup;
    failure_stage = "helper-maps-check";
    if (!verify_maps_against_elf(maps, maps_size, &helper_mapping, helper_bytes, (size_t)helper_capture.size, 1)) goto cleanup;

    failure_stage = "interpreter-resolution";
    if (realpath(helper_elf.interpreter, interpreter_resolved_path) == NULL
        || !safe_mapped_path(interpreter_resolved_path)
        || stat(interpreter_resolved_path, &interpreter_stat) != 0 || !S_ISREG(interpreter_stat.st_mode)
        || !find_mapping_by_stat(maps, maps_size, &interpreter_stat, &loader_mapping)
        || strcmp(loader_mapping.path, interpreter_resolved_path) != 0) goto cleanup;
    failure_stage = "interpreter-family";
    if (strcmp(base_name(helper_elf.interpreter), "ld-musl-aarch64.so.1") == 0) {
        (void)snprintf(runtime, sizeof(runtime), "%s", "musl");
        libc_mapping = loader_mapping;
    } else if (strcmp(base_name(helper_elf.interpreter), "ld-linux-aarch64.so.1") == 0) {
        (void)snprintf(runtime, sizeof(runtime), "%s", "glibc");
        if (!find_glibc_libc_mapping(maps, maps_size, &libc_mapping)
            || same_mapping(&libc_mapping, &loader_mapping)) goto cleanup;
    } else {
        goto cleanup;
    }
#if defined(__GLIBC__)
    if (strcmp(runtime, "glibc") != 0) goto cleanup;
#else
    if (strcmp(runtime, "musl") != 0) goto cleanup;
#endif

    failure_stage = "runtime-open-and-snapshot";
    {
        int libc_path_length = snprintf(libc_absolute_path, sizeof(libc_absolute_path), "%s", libc_mapping.path);
        int loader_path_length = snprintf(loader_absolute_path, sizeof(loader_absolute_path), "%s", loader_mapping.path);
        if (libc_path_length < 0 || (size_t)libc_path_length >= sizeof(libc_absolute_path)
            || loader_path_length < 0 || (size_t)loader_path_length >= sizeof(loader_absolute_path)) goto cleanup;
    }
    libc_fd = open(libc_absolute_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    loader_fd = open(loader_absolute_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (libc_fd < 0 || loader_fd < 0) goto cleanup;
    if (!capture_regular_file(
            libc_fd,
            directory_fd,
            "libc.elf",
            relative_directory,
            &libc_mapping,
            &total_bytes,
            &libc_capture,
            &libc_bytes)) goto cleanup;
    libc_size = (size_t)libc_capture.size;
    if (same_mapping(&libc_mapping, &loader_mapping)) {
        char relative_loader[IDENTITY_RELPATH_CAPACITY];
        int relative_loader_length = snprintf(relative_loader, sizeof(relative_loader), "%s/loader.elf", relative_directory);
        if (relative_loader_length < 0 || (size_t)relative_loader_length >= sizeof(relative_loader)) goto cleanup;
        if ((uint64_t)libc_size > MAX_IDENTITY_TOTAL_BYTES - total_bytes) goto cleanup;
        if (!retain_bytes(directory_fd, "loader.elf", libc_bytes, libc_size)) goto cleanup;
        total_bytes += (uint64_t)libc_size;
        loader_capture = libc_capture;
        (void)snprintf(loader_capture.retained_path, sizeof(loader_capture.retained_path), "%s", relative_loader);
        loader_bytes = (uint8_t *)malloc(libc_size);
        if (loader_bytes == NULL) goto cleanup;
        memcpy(loader_bytes, libc_bytes, libc_size);
    } else {
        if (!capture_regular_file(
                loader_fd,
                directory_fd,
                "loader.elf",
                relative_directory,
                &loader_mapping,
                &total_bytes,
                &loader_capture,
                &loader_bytes)) goto cleanup;
    }
    failure_stage = "libc-elf-parse";
    if (!parse_elf_identity(libc_bytes, libc_size, &libc_elf, 0) || libc_elf.type != ET_DYN) goto cleanup;
    failure_stage = "libc-maps-check";
    if (!verify_maps_against_elf(maps, maps_size, &libc_mapping, libc_bytes, libc_size, 1)) goto cleanup;
    failure_stage = "loader-elf-parse";
    if (!parse_elf_identity(loader_bytes, (size_t)loader_capture.size, &loader_elf, 0) || loader_elf.type != ET_DYN) goto cleanup;
    failure_stage = "loader-maps-check";
    if (!verify_maps_against_elf(maps, maps_size, &loader_mapping, loader_bytes, (size_t)loader_capture.size, 1)) goto cleanup;

    failure_stage = "runtime-version-check";
    if (strcmp(runtime, "musl") == 0) {
        if (!parse_version_marker(libc_bytes, libc_size, "Version ", 1, version)) goto cleanup;
        (void)snprintf(version_source, sizeof(version_source), "%s", "musl-loader-version-marker");
    } else {
        if (!parse_version_marker(libc_bytes, libc_size, "release version ", 0, version)) goto cleanup;
#if defined(__GLIBC__)
        if (strcmp(gnu_get_libc_version(), version) != 0) goto cleanup;
#endif
        (void)snprintf(version_source, sizeof(version_source), "%s", "glibc-libc-release-version-marker");
    }
    failure_stage = "identity-record-write";
    if (!write_identity_json(
            directory_fd,
            relative_directory,
            role,
            image_sha256,
            runtime,
            version,
            version_source,
            helper_elf.interpreter,
            interpreter_resolved_path,
            maps_relative_path,
            maps_sha256,
            &total_bytes,
            &helper_capture,
            &libc_capture,
            &loader_capture,
            &identity_bytes,
            &identity_size)) goto cleanup;
    digest_hex(identity_bytes, identity_size, identity_sha256);
    (void)memcpy(identity_relative_path, relative_identity_path, strlen(relative_identity_path) + 1U);
    result = 1;

cleanup:
    if (!result) (void)fprintf(stderr, "native runtime identity failed at %s\n", failure_stage);
    if (helper_fd >= 0) (void)close(helper_fd);
    if (libc_fd >= 0) (void)close(libc_fd);
    if (loader_fd >= 0) (void)close(loader_fd);
    if (directory_fd >= 0) (void)close(directory_fd);
    free(maps);
    free(helper_bytes);
    free(libc_bytes);
    free(loader_bytes);
    free(identity_bytes);
    return result;
}
