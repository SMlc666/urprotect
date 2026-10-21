#define _GNU_SOURCE

#include "host_image_validation.h"
#include "sha256.h"
#include "urp/host_adapter.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_PROVIDER_BYTES (8U * 1024U * 1024U)
#define MAX_IMAGE_BYTES (128U * 1024U * 1024U)
#define MAX_MAPPING_LINE 4096U
#define EXTERNAL_TABLE_SIZE 16U
#define EXTERNAL_TABLE_ENTRIES 4U

extern char **environ;

typedef struct mapped_range {
    char permissions[5];
    char line[MAX_MAPPING_LINE];
} mapped_range;

static int read_bounded_file(const char *path, size_t maximum, uint8_t **bytes_out, size_t *size_out)
{
    int fd = -1;
    struct stat before;
    struct stat after;
    uint8_t *bytes = NULL;
    size_t size;
    size_t position = 0U;
    uint8_t probe;

    if (path == NULL || bytes_out == NULL || size_out == NULL) return 0;
    *bytes_out = NULL;
    *size_out = 0U;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &before) != 0 || !S_ISREG(before.st_mode)
        || before.st_size <= 0 || (uint64_t)before.st_size > (uint64_t)maximum
        || (uint64_t)before.st_size > (uint64_t)SIZE_MAX) {
        if (fd >= 0) (void)close(fd);
        return 0;
    }

    size = (size_t)before.st_size;
    bytes = (uint8_t *)malloc(size);
    if (bytes == NULL) {
        (void)close(fd);
        return 0;
    }
    while (position < size) {
        ssize_t count = read(fd, bytes + position, size - position);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            free(bytes);
            (void)close(fd);
            return 0;
        }
        position += (size_t)count;
    }
    ssize_t extra;
    do {
        extra = read(fd, &probe, 1U);
    } while (extra < 0 && errno == EINTR);
    if (extra != 0 || fstat(fd, &after) != 0
        || before.st_dev != after.st_dev || before.st_ino != after.st_ino
        || before.st_size != after.st_size || before.st_mtim.tv_sec != after.st_mtim.tv_sec
        || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec) {
        free(bytes);
        (void)close(fd);
        return 0;
    }
    if (close(fd) != 0) {
        free(bytes);
        return 0;
    }
    *bytes_out = bytes;
    *size_out = size;
    return 1;
}

static int valid_lower_hex(const char *text, size_t expected_length)
{
    if (text == NULL || strlen(text) != expected_length) return 0;
    for (size_t index = 0U; index < expected_length; ++index) {
        char value = text[index];
        if (!((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f'))) return 0;
    }
    return 1;
}

static void digest_hex(const uint8_t *bytes, size_t size, char output[65])
{
    static const char hex[] = "0123456789abcdef";
    uint8_t digest[32];
    urp_sha256_context context;
    urp_sha256_init(&context);
    urp_sha256_update(&context, bytes, size);
    urp_sha256_final(&context, digest);
    for (size_t index = 0U; index < sizeof(digest); ++index) {
        output[index * 2U] = hex[digest[index] >> 4U];
        output[index * 2U + 1U] = hex[digest[index] & 0x0fU];
    }
    output[64] = '\0';
}

static uint32_t read_u32_le(const uint8_t *bytes)
{
    return (uint32_t)bytes[0]
        | ((uint32_t)bytes[1] << 8U)
        | ((uint32_t)bytes[2] << 16U)
        | ((uint32_t)bytes[3] << 24U);
}

static void bytes_hex(const uint8_t *bytes, size_t size, char *output)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t index = 0U; index < size; ++index) {
        output[index * 2U] = hex[bytes[index] >> 4U];
        output[index * 2U + 1U] = hex[bytes[index] & 0x0fU];
    }
    output[size * 2U] = '\0';
}

static int address_mapping(uintptr_t address, mapped_range *range_out)
{
    FILE *maps = fopen("/proc/self/maps", "r");
    char line[MAX_MAPPING_LINE];
    int found = 0;
    if (maps == NULL || range_out == NULL) {
        if (maps != NULL) (void)fclose(maps);
        return 0;
    }
    while (fgets(line, (int)sizeof(line), maps) != NULL) {
        unsigned long long start;
        unsigned long long end;
        unsigned long long offset;
        unsigned long long inode;
        unsigned int device_major;
        unsigned int device_minor;
        char permissions[5] = {0};
        int fields = sscanf(line, "%llx-%llx %4s %llx %x:%x %llu",
            &start, &end, permissions, &offset, &device_major, &device_minor, &inode);
        (void)offset;
        (void)device_major;
        (void)device_minor;
        (void)inode;
        if (fields != 7 || (uint64_t)address < (uint64_t)start
            || (uint64_t)address >= (uint64_t)end) continue;
        memcpy(range_out->permissions, permissions, sizeof(range_out->permissions));
        size_t line_length = strnlen(line, sizeof(line));
        while (line_length != 0U && (line[line_length - 1U] == '\n' || line[line_length - 1U] == '\r')) {
            line[--line_length] = '\0';
        }
        if (line_length >= sizeof(range_out->line)) line_length = sizeof(range_out->line) - 1U;
        memcpy(range_out->line, line, line_length);
        range_out->line[line_length] = '\0';
        found = 1;
        break;
    }
    if (fclose(maps) != 0) return 0;
    return found;
}

static int range_is_in_same_mapping(uintptr_t start, size_t size, mapped_range *range_out)
{
    mapped_range first;
    mapped_range last;
    if (size == 0U || start > UINTPTR_MAX - (size - 1U)
        || !address_mapping(start, &first)
        || !address_mapping(start + size - 1U, &last)
        || strcmp(first.line, last.line) != 0
        || strcmp(first.permissions, last.permissions) != 0) {
        return 0;
    }
    if (range_out != NULL) *range_out = first;
    return 1;
}

static int no_mapping_at(uintptr_t address)
{
    mapped_range ignored;
    return !address_mapping(address, &ignored);
}

static void write_json_string(FILE *stream, const char *value)
{
    (void)fputc('"', stream);
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor != 0U; ++cursor) {
        switch (*cursor) {
            case '"': (void)fputs("\\\"", stream); break;
            case '\\': (void)fputs("\\\\", stream); break;
            case '\b': (void)fputs("\\b", stream); break;
            case '\f': (void)fputs("\\f", stream); break;
            case '\n': (void)fputs("\\n", stream); break;
            case '\r': (void)fputs("\\r", stream); break;
            case '\t': (void)fputs("\\t", stream); break;
            default:
                if (*cursor < 0x20U) (void)fprintf(stream, "\\u%04x", (unsigned int)*cursor);
                else (void)fputc((int)*cursor, stream);
                break;
        }
    }
    (void)fputc('"', stream);
}

static int write_record(
    const char *record_path,
    const char *status,
    const char *image_sha256,
    const char *entry_symbol,
    unsigned int argument_index,
    int32_t entry_status,
    unsigned int process_status,
    const char *provider_soname,
    const char *provider_build_id,
    const char *provider_sha256,
    uintptr_t provider_load_bias,
    uintptr_t consumer_load_bias,
    uintptr_t table_address,
    uint64_t table_virtual_address,
    const char *table_bytes_hex,
    const char *table_permissions,
    const char *table_mapping_line,
    const char *provider_mapped_path,
    const char *consumer_mapped_path,
    uintptr_t entry_address,
    uintptr_t got_address,
    uint64_t got_virtual_address,
    uintptr_t got_value,
    const char *got_permissions,
    const char *got_mapping_line,
    const uintptr_t target_addresses[EXTERNAL_TABLE_ENTRIES],
    size_t dependency_count,
    int image_sealed,
    int table_file_bytes_match,
    int table_unchanged_after_dispatch,
    int maps_isolated,
    int provider_released,
    int32_t release_status,
    const char *failure_stage)
{
    char temporary[4096];
    FILE *stream;
    int written = snprintf(temporary, sizeof(temporary), "%s.tmp", record_path);
    if (written < 0 || (size_t)written >= sizeof(temporary)) return 0;
    stream = fopen(temporary, "w");
    if (stream == NULL) return 0;
    (void)fprintf(stream, "{\n  \"schemaVersion\": 1,\n  \"status\": ");
    write_json_string(stream, status);
    (void)fprintf(stream, ",\n  \"loaderId\": \"host-context.sealed-memfd.dlmopen-provider\",\n  \"nativeImageSha256\": ");
    write_json_string(stream, image_sha256);
    (void)fprintf(stream, ",\n  \"entrySymbol\": ");
    write_json_string(stream, entry_symbol);
    (void)fprintf(stream, ",\n  \"argumentIndex\": %u,\n  \"entryAddress\": %" PRIuPTR
        ",\n  \"entryStatus\": %" PRId32 ",\n  \"processStatus\": %u,\n  \"releaseStatus\": \"%s\",\n"
        "  \"releaseStatusCode\": %" PRId32 ",\n  \"releaseOrder\": \"dispatch-before-release-image\",\n"
        "  \"providerSoname\": ",
        argument_index, entry_address, entry_status, process_status,
        release_status == (int32_t)URP_STATUS_OK ? "passed" : "failed", release_status);
    write_json_string(stream, provider_soname);
    (void)fprintf(stream, ",\n  \"providerBuildId\": ");
    write_json_string(stream, provider_build_id);
    (void)fprintf(stream, ",\n  \"providerSha256\": ");
    write_json_string(stream, provider_sha256);
    (void)fprintf(stream, ",\n  \"providerLoadBias\": %" PRIuPTR ",\n  \"consumerLoadBias\": %" PRIuPTR
        ",\n  \"providerTableVirtualAddress\": %" PRIu64 ",\n  \"providerTableAddress\": %" PRIuPTR
        ",\n  \"providerTableBytes\": ",
        provider_load_bias, consumer_load_bias, table_virtual_address, table_address);
    write_json_string(stream, table_bytes_hex);
    (void)fprintf(stream, ",\n  \"providerTablePermissions\": ");
    write_json_string(stream, table_permissions);
    (void)fprintf(stream, ",\n  \"providerTableMapping\": ");
    write_json_string(stream, table_mapping_line);
    (void)fprintf(stream, ",\n  \"providerMappedPath\": ");
    write_json_string(stream, provider_mapped_path);
    (void)fprintf(stream, ",\n  \"consumerMappedPath\": ");
    write_json_string(stream, consumer_mapped_path);
    (void)fprintf(stream, ",\n  \"providerTargetAddresses\": [");
    for (size_t index = 0U; index < EXTERNAL_TABLE_ENTRIES; ++index) {
        (void)fprintf(stream, "%s%" PRIuPTR, index == 0U ? "" : ", ", target_addresses[index]);
    }
    (void)fprintf(stream, "],\n  \"gotVirtualAddress\": %" PRIu64 ",\n  \"gotAddress\": %" PRIuPTR
        ",\n  \"gotValue\": %" PRIuPTR ",\n  \"gotPermissions\": ",
        got_virtual_address, got_address, got_value);
    write_json_string(stream, got_permissions);
    (void)fprintf(stream, ",\n  \"gotMapping\": ");
    write_json_string(stream, got_mapping_line);
    (void)fprintf(stream, ",\n  \"dependencyCount\": %zu,\n  \"usesConfiguredProvider\": true,\n"
        "  \"imageSealed\": %s,\n  \"providerTableFileBytesMatch\": %s,\n"
        "  \"providerTableUnchangedAfterDispatch\": %s,\n  \"providerConsumerMapsIsolated\": %s,\n"
        "  \"providerReleasedAfterConsumer\": %s,\n  \"firstFailureStage\": %s\n}\n",
        dependency_count, image_sealed ? "true" : "false",
        table_file_bytes_match ? "true" : "false",
        table_unchanged_after_dispatch ? "true" : "false",
        maps_isolated ? "true" : "false", provider_released ? "true" : "false",
        failure_stage == NULL ? "null" : "\"host-context-dispatch\"");
    if (fclose(stream) != 0 || rename(temporary, record_path) != 0) {
        (void)unlink(temporary);
        return 0;
    }
    return 1;
}

int main(int argc, char **argv)
{
    const char *provider_path;
    const char *provider_soname;
    const char *provider_build_id;
    const char *provider_sha256;
    const char *image_path;
    const char *entry_symbol;
    const char *record_path;
    unsigned long parsed_index;
    char *index_end = NULL;
    uint8_t *provider_bytes = NULL;
    uint8_t *image_bytes = NULL;
    size_t provider_size = 0U;
    size_t image_size = 0U;
    char actual_provider_sha256[65] = {0};
    char image_sha256[65] = {0};
    char table_bytes_hex[EXTERNAL_TABLE_SIZE * 2U + 1U] = {0};
    urp_host_external_provider_facts provider_facts;
    urp_host_provider_config_v1 provider_config;
    urp_host_adapter_v1 adapter;
    urp_image_handle handle = 0U;
    size_t dependency_count = 0U;
    int uses_provider = 0;
    uint64_t got_virtual_address = 0U;
    uintptr_t entry_address = 0U;
    uintptr_t companion_address = 0U;
    uintptr_t provider_table_address = 0U;
    uintptr_t provider_load_bias = 0U;
    uintptr_t consumer_load_bias = 0U;
    uintptr_t table_address = 0U;
    uintptr_t target_addresses[EXTERNAL_TABLE_ENTRIES] = {0U};
    uintptr_t got_address = 0U;
    uintptr_t got_value = 0U;
    struct link_map *provider_map = NULL;
    struct link_map *consumer_map = NULL;
    Dl_info provider_info;
    Dl_info consumer_info;
    mapped_range table_mapping;
    mapped_range got_mapping;
    char provider_path_runtime[MAX_MAPPING_LINE] = {0};
    char consumer_path_runtime[MAX_MAPPING_LINE] = {0};
    uint8_t table_before[EXTERNAL_TABLE_SIZE] = {0};
    uint8_t table_after[EXTERNAL_TABLE_SIZE] = {0};
    int32_t entry_status = -1;
    int32_t release_status = (int32_t)URP_STATUS_LOAD_FAILED;
    unsigned int process_status = 1U;
    const char *final_status = "failed";
    unsigned int expected_statuses[5] = {17U, 103U, 249U, 91U, 255U};
    int provider_released = 0;
    int table_file_bytes_match = 0;
    int table_unchanged = 0;
    int image_sealed = 0;
    int maps_isolated = 0;
    int operation_ok = 0;

    if (argc != 9) {
        (void)fprintf(stderr, "usage: %s provider-path soname build-id sha256 image symbol index record\n", argv[0]);
        return 2;
    }
    provider_path = argv[1];
    provider_soname = argv[2];
    provider_build_id = argv[3];
    provider_sha256 = argv[4];
    image_path = argv[5];
    entry_symbol = argv[6];
    record_path = argv[8];
    parsed_index = strtoul(argv[7], &index_end, 10);
    if (strcmp(provider_soname, URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME) != 0
        || !valid_lower_hex(provider_build_id, 40U)
        || !valid_lower_hex(provider_sha256, 64U)
        || (strcmp(entry_symbol, "urp_entry") != 0 && strcmp(entry_symbol, "urp_observer") != 0)
        || index_end == argv[7] || *index_end != '\0' || parsed_index > 4U) {
        (void)fprintf(stderr, "provider handoff arguments do not satisfy the bounded fixture contract\n");
        return 2;
    }
    if (!read_bounded_file(provider_path, MAX_PROVIDER_BYTES, &provider_bytes, &provider_size)
        || !read_bounded_file(image_path, MAX_IMAGE_BYTES, &image_bytes, &image_size)) {
        (void)fprintf(stderr, "provider/consumer input read failed its regular-file bound\n");
        free(provider_bytes);
        free(image_bytes);
        return 1;
    }
    digest_hex(provider_bytes, provider_size, actual_provider_sha256);
    if (strcmp(actual_provider_sha256, provider_sha256) != 0
        || urp_host_external_provider_validate(provider_bytes, provider_size, provider_soname,
            provider_build_id, &provider_facts) != URP_STATUS_OK
        || urp_host_image_validate_with_provider(image_bytes, image_size, provider_soname,
            &dependency_count, &uses_provider, &got_virtual_address) != URP_STATUS_OK
        || !uses_provider || dependency_count != 1U || got_virtual_address == 0U) {
        (void)fprintf(stderr, "pinned provider or consumer preflight failed before loader handoff\n");
        free(provider_bytes);
        free(image_bytes);
        return 1;
    }

    provider_config.path = provider_path;
    provider_config.expected_soname = provider_soname;
    provider_config.expected_build_id_hex = provider_build_id;
    provider_config.expected_sha256_hex = provider_sha256;
    if (urp_host_adapter_init_with_provider(&adapter, &provider_config) != URP_STATUS_OK
        || adapter.context.load_image(adapter.context.userdata, image_bytes, image_size,
            URP_LOAD_IMAGE_IMMUTABLE, &handle) != URP_STATUS_OK
        || handle == 0U) {
        (void)fprintf(stderr, "configured provider HostContext load failed\n");
        free(provider_bytes);
        free(image_bytes);
        return 1;
    }
    image_sealed = urp_host_adapter_image_is_sealed(handle) != 0;
    if (!image_sealed
        || adapter.context.lookup_symbol(adapter.context.userdata, handle, entry_symbol, NULL,
            &entry_address) != URP_STATUS_OK
        || adapter.context.lookup_symbol(adapter.context.userdata, handle,
            strcmp(entry_symbol, "urp_entry") == 0 ? "urp_observer" : "urp_entry",
            NULL, &companion_address) != URP_STATUS_OK
        || adapter.context.lookup_symbol(adapter.context.userdata, handle,
            URP_HOST_EXTERNAL_TABLE_SYMBOL, NULL, &provider_table_address) != URP_STATUS_OK
        || entry_address == 0U || companion_address == 0U || provider_table_address == 0U
        || dladdr1((void *)provider_table_address, &provider_info, (void **)&provider_map, RTLD_DL_LINKMAP) == 0
        || provider_map == NULL
        || dladdr1((void *)entry_address, &consumer_info, (void **)&consumer_map, RTLD_DL_LINKMAP) == 0
        || consumer_map == NULL || provider_map == consumer_map
        || provider_info.dli_fname == NULL || consumer_info.dli_fname == NULL
        || strnlen(provider_info.dli_fname, sizeof(provider_path_runtime)) >= sizeof(provider_path_runtime)
        || strnlen(consumer_info.dli_fname, sizeof(consumer_path_runtime)) >= sizeof(consumer_path_runtime)
        || (uint64_t)provider_map->l_addr > (uint64_t)UINTPTR_MAX - provider_facts.table_virtual_address
        || provider_table_address != (uintptr_t)provider_map->l_addr + (uintptr_t)provider_facts.table_virtual_address
        || (uint64_t)consumer_map->l_addr > (uint64_t)UINTPTR_MAX - got_virtual_address) {
        (void)fprintf(stderr, "loaded provider/consumer mappings did not match the validated image facts\n");
        (void)adapter.context.release_image(adapter.context.userdata, handle);
        free(provider_bytes);
        free(image_bytes);
        return 1;
    }
    memcpy(provider_path_runtime, provider_info.dli_fname, strlen(provider_info.dli_fname) + 1U);
    memcpy(consumer_path_runtime, consumer_info.dli_fname, strlen(consumer_info.dli_fname) + 1U);
    maps_isolated = provider_map != consumer_map;
    if (!range_is_in_same_mapping(provider_table_address, EXTERNAL_TABLE_SIZE, &table_mapping)
        || table_mapping.permissions[0] != 'r' || table_mapping.permissions[1] != '-'
        || table_mapping.permissions[2] != '-'
        || !range_is_in_same_mapping((uintptr_t)consumer_map->l_addr + (uintptr_t)got_virtual_address,
            sizeof(uintptr_t), &got_mapping)
        || got_mapping.permissions[0] != 'r' || got_mapping.permissions[2] == 'x') {
        (void)fprintf(stderr, "provider table or consumer GLOB_DAT mapping permissions are invalid\n");
        (void)adapter.context.release_image(adapter.context.userdata, handle);
        free(provider_bytes);
        free(image_bytes);
        return 1;
    }
    provider_load_bias = (uintptr_t)provider_map->l_addr;
    consumer_load_bias = (uintptr_t)consumer_map->l_addr;
    table_address = provider_table_address;
    got_address = consumer_load_bias + (uintptr_t)got_virtual_address;
    memcpy(&got_value, (const void *)got_address, sizeof(got_value));
    memcpy(table_before, (const void *)table_address, sizeof(table_before));
    digest_hex(image_bytes, image_size, image_sha256);
    table_file_bytes_match = memcmp(table_before, provider_facts.table_bytes, sizeof(table_before)) == 0;
    if (got_value != table_address || !table_file_bytes_match) {
        (void)fprintf(stderr, "runtime GOT or provider table bytes do not match the pinned provider facts\n");
        (void)adapter.context.release_image(adapter.context.userdata, handle);
        free(provider_bytes);
        free(image_bytes);
        return 1;
    }
    for (size_t index = 0U; index < EXTERNAL_TABLE_ENTRIES; ++index) {
        uint32_t raw = read_u32_le(provider_facts.table_bytes + index * sizeof(uint32_t));
        int64_t displacement = (raw & UINT32_C(0x80000000)) != 0U
            ? (int64_t)raw - INT64_C(0x100000000) : (int64_t)raw;
        if (displacement < 0) {
            uint64_t magnitude = (uint64_t)(-displacement);
            if (magnitude > (uint64_t)table_address) {
                (void)fprintf(stderr, "provider target displacement underflows its table base\n");
                (void)adapter.context.release_image(adapter.context.userdata, handle);
                free(provider_bytes);
                free(image_bytes);
                return 1;
            }
            target_addresses[index] = table_address - (uintptr_t)magnitude;
        } else {
            uint64_t magnitude = (uint64_t)displacement;
            if (magnitude > (uint64_t)UINTPTR_MAX - table_address) {
                (void)fprintf(stderr, "provider target displacement overflows its table base\n");
                (void)adapter.context.release_image(adapter.context.userdata, handle);
                free(provider_bytes);
                free(image_bytes);
                return 1;
            }
            target_addresses[index] = table_address + (uintptr_t)magnitude;
        }
        struct link_map *target_map = NULL;
        Dl_info target_info;
        if (dladdr1((void *)target_addresses[index], &target_info,
                (void **)&target_map, RTLD_DL_LINKMAP) == 0 || target_map != provider_map) {
            (void)fprintf(stderr, "provider table target is not owned by the pinned provider map\n");
            (void)adapter.context.release_image(adapter.context.userdata, handle);
            free(provider_bytes);
            free(image_bytes);
            return 1;
        }
    }

    urp_entry_fn entry = NULL;
    memcpy(&entry, &entry_address, sizeof(entry));
    const char *const call_argv[] = { "external-provider-fixture", NULL };
    urp_launch_args_v1 launch_args = {
        .abi_version = URP_HOST_ABI_VERSION,
        .struct_size = sizeof(urp_launch_args_v1),
        .argc = (uint32_t)parsed_index,
        .argv = call_argv,
        .envp = (const char *const *)environ,
        .image = 0U,
    };
    entry_status = entry(&adapter.context, &launch_args);
    process_status = ((uint32_t)entry_status) & 0xffU;
    memcpy(table_after, (const void *)table_address, sizeof(table_after));
    table_unchanged = memcmp(table_after, table_before, sizeof(table_before)) == 0;
    release_status = (int32_t)adapter.context.release_image(adapter.context.userdata, handle);
    handle = 0U;
    provider_released = release_status == (int32_t)URP_STATUS_OK && no_mapping_at(table_address);
    operation_ok = release_status == (int32_t)URP_STATUS_OK && provider_released
        && process_status == expected_statuses[parsed_index]
        && table_file_bytes_match && table_unchanged && maps_isolated && image_sealed;
    final_status = operation_ok ? "passed" : "failed";
    bytes_hex(provider_facts.table_bytes, sizeof(provider_facts.table_bytes), table_bytes_hex);
    if (!write_record(record_path, final_status, image_sha256, entry_symbol, (unsigned int)parsed_index,
            entry_status, process_status, provider_soname, provider_build_id, provider_sha256,
            provider_load_bias, consumer_load_bias,
            table_address, provider_facts.table_virtual_address, table_bytes_hex,
            table_mapping.permissions, table_mapping.line, provider_path_runtime, consumer_path_runtime,
            entry_address, got_address, got_virtual_address, got_value, got_mapping.permissions,
            got_mapping.line, target_addresses, dependency_count, image_sealed,
            table_file_bytes_match, table_unchanged, maps_isolated, provider_released, release_status,
            operation_ok ? NULL : "host-context-dispatch")) {
        (void)fprintf(stderr, "could not atomically write provider handoff record\n");
        free(provider_bytes);
        free(image_bytes);
        return 1;
    }
    free(provider_bytes);
    free(image_bytes);
    return (int)process_status;
}
