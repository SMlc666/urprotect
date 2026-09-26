#define _GNU_SOURCE

#include "urp/host_adapter.h"
#include "host_context_graph_fixture_contract.h"
#include "host_image_validation.h"

#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int read_image(const char *path, uint8_t **bytes_out, size_t *size_out)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL || fseek(file, 0L, SEEK_END) != 0) {
        if (file != NULL) (void)fclose(file);
        return 0;
    }
    long length = ftell(file);
    if (length <= 0L || fseek(file, 0L, SEEK_SET) != 0) {
        (void)fclose(file);
        return 0;
    }
    if ((uint64_t)length > (uint64_t)SIZE_MAX) {
        (void)fclose(file);
        return 0;
    }
    size_t size = (size_t)length;
    uint8_t *bytes = (uint8_t *)malloc(size);
    if (bytes == NULL || fread(bytes, 1U, size, file) != size || ferror(file) != 0) {
        free(bytes);
        (void)fclose(file);
        return 0;
    }
    (void)fclose(file);
    *bytes_out = bytes;
    *size_out = size;
    return 1;
}

static int count_open_descriptors(size_t *count_out)
{
    DIR *directory = opendir("/proc/self/fd");
    if (directory == NULL) {
        return 0;
    }
    size_t count = 0U;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            ++count;
        }
    }
    if (closedir(directory) != 0) {
        return 0;
    }
    *count_out = count;
    return 1;
}


static uint32_t read_u32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8U)
        | ((uint32_t)bytes[2] << 16U) | ((uint32_t)bytes[3] << 24U);
}

static uint64_t read_u64(const uint8_t *bytes)
{
    uint64_t value = 0U;
    for (size_t index = 0U; index < 8U; ++index) {
        value |= (uint64_t)bytes[index] << (index * 8U);
    }
    return value;
}

static void write_u64(uint8_t *bytes, uint64_t value)
{
    for (size_t index = 0U; index < 8U; ++index) {
        bytes[index] = (uint8_t)(value >> (index * 8U));
    }
}

typedef struct graph_dynamic_locations {
    size_t first_needed_value;
    size_t second_needed_value;
    size_t terminator;
    size_t dynamic_end;
    size_t string_table_file_offset;
    size_t string_table_size;
} graph_dynamic_locations;

static int locate_dynamic(
    const uint8_t *bytes,
    size_t size,
    graph_dynamic_locations *locations)
{
    if (size < 64U) {
        return 0;
    }
    uint64_t phoff = read_u64(bytes + 32U);
    uint16_t phnum = (uint16_t)bytes[56U] | (uint16_t)((uint16_t)bytes[57U] << 8U);
    if (phoff > (uint64_t)size
        || (uint64_t)phnum * 56U > (uint64_t)size - phoff) {
        return 0;
    }
    uint64_t dynoff = 0U, dynsize = 0U, strtab = 0U, strsz = 0U;
    size_t dynamic_segments = 0U;
    for (uint16_t i = 0U; i < phnum; ++i) {
        const uint8_t *ph = bytes + (size_t)phoff + (size_t)i * 56U;
        if (read_u32(ph) == 2U) {
            ++dynamic_segments;
            dynoff = read_u64(ph + 8U);
            dynsize = read_u64(ph + 32U);
        }
    }
    if (dynamic_segments != 1U || dynoff > (uint64_t)size
        || dynsize > (uint64_t)size - dynoff || dynsize % 16U != 0U) {
        return 0;
    }
    memset(locations, 0, sizeof(*locations));
    locations->dynamic_end = (size_t)(dynoff + dynsize);
    locations->first_needed_value = SIZE_MAX;
    locations->second_needed_value = SIZE_MAX;
    locations->terminator = SIZE_MAX;
    size_t count = (size_t)(dynsize / 16U);
    for (size_t i = 0U; i < count; ++i) {
        size_t off = (size_t)dynoff + i * 16U;
        uint64_t tag = read_u64(bytes + off);
        if (tag == 0U) {
            locations->terminator = off;
            break;
        }
        if (tag == 1U) {
            if (locations->first_needed_value == SIZE_MAX) {
                locations->first_needed_value = off + 8U;
            } else if (locations->second_needed_value == SIZE_MAX) {
                locations->second_needed_value = off + 8U;
            } else {
                return 0;
            }
        } else if (tag == 5U) {
            strtab = read_u64(bytes + off + 8U);
        } else if (tag == 10U) {
            strsz = read_u64(bytes + off + 8U);
        }
    }
    if (locations->first_needed_value == SIZE_MAX || locations->second_needed_value == SIZE_MAX
        || locations->terminator == SIZE_MAX || strsz == 0U || strsz > (uint64_t)SIZE_MAX) {
        return 0;
    }
    for (uint16_t i = 0U; i < phnum; ++i) {
        const uint8_t *ph = bytes + (size_t)phoff + (size_t)i * 56U;
        if (read_u32(ph) != 1U) continue;
        uint64_t offset = read_u64(ph + 8U), address = read_u64(ph + 16U), filesz = read_u64(ph + 32U);
        if (strtab >= address && strtab - address <= filesz
            && strsz <= filesz - (strtab - address)
            && strtab - address <= UINT64_MAX - offset) {
            uint64_t file = offset + (strtab - address);
            if (file <= (uint64_t)size && strsz <= (uint64_t)size - file) {
                locations->string_table_file_offset = (size_t)file;
                locations->string_table_size = (size_t)strsz;
                return 1;
            }
        }
    }
    return 0;
}

static size_t needed_cell_for_name(
    const uint8_t *bytes,
    const graph_dynamic_locations *locations,
    const char *wanted)
{
    const size_t cells[] = {
        locations->first_needed_value,
        locations->second_needed_value
    };
    for (size_t index = 0U; index < sizeof(cells) / sizeof(cells[0]); ++index) {
        uint64_t name_offset = read_u64(bytes + cells[index]);
        if (name_offset < (uint64_t)locations->string_table_size
            && strcmp((const char *)(bytes + locations->string_table_file_offset
                + (size_t)name_offset), wanted) == 0) {
            return cells[index];
        }
    }
    return SIZE_MAX;
}

static int expect_mutation_rejected(
    urp_host_adapter_v1 *adapter,
    const uint8_t *source,
    size_t size,
    const graph_dynamic_locations *locations,
    const char *kind)
{
    uint8_t *mutant = (uint8_t *)malloc(size);
    if (mutant == NULL) {
        return 0;
    }
    memcpy(mutant, source, size);
    size_t null_offset = locations->terminator;
    if (strcmp(kind, "third-needed") == 0) {
        if (null_offset > locations->dynamic_end
            || locations->dynamic_end - null_offset < 2U * 16U) {
            free(mutant);
            return 0;
        }
        write_u64(mutant + null_offset, 1U);
        write_u64(mutant + null_offset + 8U,
            read_u64(mutant + locations->first_needed_value));
        write_u64(mutant + null_offset + 16U, 0U);
    } else if (strcmp(kind, "duplicate-libc") == 0
        || strcmp(kind, "duplicate-loader") == 0) {
        const char *name = strcmp(kind, "duplicate-libc") == 0
            ? "libc.so.6" : "ld-linux-aarch64.so.1";
        size_t source_cell = needed_cell_for_name(source, locations, name);
        if (source_cell == SIZE_MAX) {
            free(mutant);
            return 0;
        }
        size_t target_cell = source_cell == locations->first_needed_value
            ? locations->second_needed_value : locations->first_needed_value;
        write_u64(mutant + target_cell, read_u64(mutant + source_cell));
    } else if (strcmp(kind, "missing-libc") == 0) {
        size_t libc_cell = needed_cell_for_name(source, locations, "libc.so.6");
        if (libc_cell == SIZE_MAX) {
            free(mutant);
            return 0;
        }
        write_u64(mutant + libc_cell, 0U);
    } else if (strcmp(kind, "unknown") == 0) {
        write_u64(mutant + locations->second_needed_value, 2U);
    } else {
        uint64_t tag = strcmp(kind, "rpath") == 0 ? 15U
            : strcmp(kind, "runpath") == 0 ? 29U
            : strcmp(kind, "auxiliary") == 0 ? UINT64_C(0x7ffffffd)
            : UINT64_C(0x7fffffff);
        write_u64(mutant + null_offset, tag);
    }
    urp_image_handle handle = UINT64_C(0xfeedface);
    urp_status status = adapter->context.load_image(
        adapter->context.userdata, mutant, size, URP_LOAD_IMAGE_IMMUTABLE, &handle);
    free(mutant);
    if (status != URP_STATUS_UNSUPPORTED || handle != 0U) {
        (void)fprintf(stderr, "%s mutation status=%d handle=%llu\n",
            kind, (int)status, (unsigned long long)handle);
        return 0;
    }
    return 1;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        return 2;
    }
    uint8_t *bytes = NULL;
    size_t size = 0U;
    if (!read_image(argv[1], &bytes, &size)) {
        return 1;
    }
    size_t dependency_count = 0U;
    urp_status preflight_status = urp_host_image_validate(bytes, size, &dependency_count);
    if (preflight_status != URP_STATUS_OK || dependency_count != 2U) {
        free(bytes);
        (void)fprintf(stderr, "dependency graph preflight status=%d count=%zu, expected OK/2\n",
            (int)preflight_status, dependency_count);
        return 1;
    }
    graph_dynamic_locations locations;
    if (!locate_dynamic(bytes, size, &locations)) {
        free(bytes);
        (void)fprintf(stderr, "could not locate pair dynamic metadata\n");
        return 1;
    }
    urp_host_adapter_v1 adapter;
    urp_host_adapter_init(&adapter);
    static const char *const mutations[] = {
        "third-needed", "duplicate-libc", "duplicate-loader", "missing-libc", "unknown",
        "rpath", "runpath", "auxiliary", "filter"
    };
    for (size_t index = 0U; index < sizeof(mutations) / sizeof(mutations[0]); ++index) {
        if (!expect_mutation_rejected(&adapter, bytes, size, &locations, mutations[index])) {
            free(bytes);
            return 1;
        }
    }
    urp_image_handle handle = UINT64_C(0xfeedface);
    if (unlink(URP_GRAPH_LIFECYCLE_MARKER_PATH) != 0
        && errno != ENOENT) {
        free(bytes);
        return 1;
    }
    urp_status status = adapter.context.load_image(
        adapter.context.userdata, bytes, size, URP_LOAD_IMAGE_IMMUTABLE, &handle);
    free(bytes);
    if (status != URP_STATUS_OK || handle == 0U) {
        (void)unlink(URP_GRAPH_LIFECYCLE_MARKER_PATH);
        (void)fprintf(stderr, "pair fixture load failed: status=%d handle=%llu\n",
            (int)status, (unsigned long long)handle);
        return 1;
    }
    uintptr_t address = 0U;
    status = adapter.context.lookup_symbol(
        adapter.context.userdata, handle, "urp_entry", NULL, &address);
    if (status != URP_STATUS_OK || address == 0U) {
        (void)adapter.context.release_image(adapter.context.userdata, handle);
        (void)unlink(URP_GRAPH_LIFECYCLE_MARKER_PATH);
        return 1;
    }
    const urp_host_context_v1 *host = &adapter.context;
    const urp_launch_args_v1 args = { .abi_version = 1U,
        .struct_size = sizeof(urp_launch_args_v1), .argc = 0U, .argv = NULL, .envp = NULL };
    int32_t entry_status = ((urp_entry_fn)(uintptr_t)address)(host, &args);
    urp_status release_status = adapter.context.release_image(
        adapter.context.userdata, handle);
    FILE *marker_file = fopen(URP_GRAPH_LIFECYCLE_MARKER_PATH, "rb");
    char marker_contents[32] = {0};
    int marker_valid = 0;
    if (marker_file != NULL) {
        marker_valid = fgets(marker_contents, (int)sizeof(marker_contents), marker_file) != NULL
            && strcmp(marker_contents, "released\n") == 0;
        if (fclose(marker_file) != 0) {
            marker_valid = 0;
        }
    }
    (void)unlink(URP_GRAPH_LIFECYCLE_MARKER_PATH);
    if (entry_status != 37 || release_status != URP_STATUS_OK || !marker_valid) {
        (void)fprintf(stderr, "pair fixture entry=%d release=%d\n",
            (int)entry_status, (int)release_status);
        return 1;
    }
    static const char *const influence_variables[] = {
        "LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT"
    };
    for (size_t index = 0U;
         index < sizeof(influence_variables) / sizeof(influence_variables[0]);
         ++index) {
        if (setenv(influence_variables[index], "TARGET", 1) != 0) {
            return 1;
        }
        size_t memfd_attempts_before = urp_host_adapter_memfd_create_attempts();
        uint8_t *negative_bytes = NULL;
        size_t negative_size = 0U;
        if (!read_image(argv[1], &negative_bytes, &negative_size)) {
            (void)unsetenv(influence_variables[index]);
            return 1;
        }
        urp_image_handle rejected_handle = UINT64_C(0xfeedface);
        status = adapter.context.load_image(
            adapter.context.userdata,
            negative_bytes,
            negative_size,
            URP_LOAD_IMAGE_IMMUTABLE,
            &rejected_handle);
        free(negative_bytes);
        (void)unsetenv(influence_variables[index]);
        if (status != URP_STATUS_UNSUPPORTED || rejected_handle != 0U
            || urp_host_adapter_memfd_create_attempts() != memfd_attempts_before) {
            (void)fprintf(stderr,
                "%s gate did not reject before memfd with zero handle\n",
                influence_variables[index]);
            return 1;
        }
    }
    uint8_t *singleton_bytes = NULL;
    size_t singleton_size = 0U;
    if (!read_image(argv[2], &singleton_bytes, &singleton_size)
        || setenv("LD_LIBRARY_PATH", "/nonexistent/urprotect-dependency-root", 1) != 0) {
        free(singleton_bytes);
        return 1;
    }
    size_t singleton_memfd_count = urp_host_adapter_memfd_create_attempts();
    urp_image_handle singleton_handle = 0U;
    status = adapter.context.load_image(
        adapter.context.userdata,
        singleton_bytes,
        singleton_size,
        URP_LOAD_IMAGE_IMMUTABLE,
        &singleton_handle);
    free(singleton_bytes);
    (void)unsetenv("LD_LIBRARY_PATH");
    size_t singleton_memfd_count_after = urp_host_adapter_memfd_create_attempts();
    urp_status singleton_release_status = singleton_handle == 0U
        ? URP_STATUS_INVALID_ARGUMENT
        : adapter.context.release_image(adapter.context.userdata, singleton_handle);
    if (status != URP_STATUS_OK || singleton_handle == 0U
        || singleton_memfd_count_after != singleton_memfd_count + 1U
        || singleton_release_status != URP_STATUS_OK) {
        (void)fprintf(stderr,
            "legacy singleton changed under pair-only LD_LIBRARY_PATH gate: status=%d handle=%llu\n",
            (int)status,
            (unsigned long long)singleton_handle);
        return 1;
    }

    uint8_t *loader_failure_bytes = NULL;
    size_t loader_failure_size = 0U;
    size_t descriptors_before = 0U;
    if (!read_image(argv[3], &loader_failure_bytes, &loader_failure_size)
        || urp_host_image_validate(loader_failure_bytes, loader_failure_size,
            &dependency_count) != URP_STATUS_OK
        || dependency_count != 2U
        || !count_open_descriptors(&descriptors_before)) {
        free(loader_failure_bytes);
        return 1;
    }
    size_t memfd_attempts_before = urp_host_adapter_memfd_create_attempts();
    urp_image_handle loader_failure_handle = UINT64_C(0xfeedface);
    urp_status loader_failure_status = adapter.context.load_image(
        adapter.context.userdata,
        loader_failure_bytes,
        loader_failure_size,
        URP_LOAD_IMAGE_IMMUTABLE,
        &loader_failure_handle);
    free(loader_failure_bytes);
    size_t descriptors_after = 0U;
    if (!count_open_descriptors(&descriptors_after)
        || loader_failure_status != URP_STATUS_LOAD_FAILED
        || loader_failure_handle != 0U
        || urp_host_adapter_memfd_create_attempts() != memfd_attempts_before + 1U
        || descriptors_after != descriptors_before) {
        (void)fprintf(stderr,
            "loader failure rollback: status=%d handle=%llu fd-count=%zu/%zu\n",
            (int)loader_failure_status,
            (unsigned long long)loader_failure_handle,
            descriptors_before,
            descriptors_after);
        return 1;
    }
    (void)puts("dependency graph pair: PASS (both orders, entry/release, env gate before memfd, singleton preserved, dlopen rollback)");
    return 0;
}
