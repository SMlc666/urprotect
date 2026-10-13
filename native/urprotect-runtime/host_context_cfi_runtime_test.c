#define _GNU_SOURCE
#include "urp/host_adapter.h"

#include <dlfcn.h>
#include <execinfo.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct cfi_state {
    uintptr_t target_address;
    uintptr_t target_end;
    size_t frame_count;
    int transformed_frame_observed;
    unsigned diagnostic_calls;
} cfi_state;

static cfi_state *active_state;

static uint16_t read_u16(const uint8_t *bytes)
{
    return (uint16_t)((uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8U));
}

static uint32_t read_u32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0]
        | ((uint32_t)bytes[1] << 8U)
        | ((uint32_t)bytes[2] << 16U)
        | ((uint32_t)bytes[3] << 24U);
}

static uint64_t read_u64(const uint8_t *bytes)
{
    uint64_t value = 0U;
    for (unsigned index = 0U; index < 8U; ++index) {
        value |= (uint64_t)bytes[index] << (index * 8U);
    }
    return value;
}

static int find_generated_executable_range(
    const uint8_t *image,
    size_t image_size,
    uintptr_t load_bias,
    uintptr_t *start_out,
    uintptr_t *end_out,
    int *is_transformed_out)
{
    if (image == NULL || image_size < 64U || start_out == NULL
        || end_out == NULL || is_transformed_out == NULL
        || image[0] != 0x7fU || image[1] != 'E' || image[2] != 'L'
        || image[3] != 'F' || image[4] != 2U || image[5] != 1U) {
        return 0;
    }

    uint64_t program_header_offset = read_u64(image + 32U);
    uint16_t entry_size = read_u16(image + 54U);
    uint16_t count = read_u16(image + 56U);
    if (entry_size != 56U || count == 0U || count > 4096U
        || program_header_offset > image_size
        || (uint64_t)count * entry_size > (uint64_t)image_size - program_header_offset) {
        return 0;
    }

    uint64_t highest_virtual = 0U;
    uint64_t highest_end = 0U;
    unsigned executable_count = 0U;
    for (uint16_t index = 0U; index < count; ++index) {
        const uint8_t *header = image + program_header_offset + (uint64_t)index * entry_size;
        if (read_u32(header) != 1U || (read_u32(header + 4U) & 1U) == 0U) continue;
        uint64_t virtual_address = read_u64(header + 16U);
        uint64_t memory_size = read_u64(header + 40U);
        if (memory_size == 0U || virtual_address > UINT64_MAX - memory_size) return 0;
        ++executable_count;
        if (virtual_address >= highest_virtual) {
            highest_virtual = virtual_address;
            highest_end = virtual_address + memory_size;
        }
    }

    if (highest_end > UINTPTR_MAX - load_bias) return 0;
    *start_out = load_bias + (uintptr_t)highest_virtual;
    *end_out = load_bias + (uintptr_t)highest_end;
    *is_transformed_out = executable_count > 1U;
    return 1;
}

static urp_status capture_diagnostic(void *userdata, uint32_t code, const char *message)
{
    (void)userdata;
    (void)code;
    (void)message;
    if (active_state == NULL) return URP_STATUS_INVALID_ARGUMENT;

    void *frames[64];
    int count = backtrace(frames, (int)(sizeof(frames) / sizeof(frames[0])));
    if (count < 0) return URP_STATUS_LOAD_FAILED;
    active_state->frame_count = (size_t)count;
    active_state->diagnostic_calls++;
    for (int index = 0; index < count; ++index) {
        uintptr_t address = (uintptr_t)frames[index];
        if (active_state->target_end > active_state->target_address
            && address >= active_state->target_address
            && address < active_state->target_end) {
            active_state->transformed_frame_observed = 1;
        }
    }
    return URP_STATUS_OK;
}

static int read_image(const char *path, uint8_t **bytes_out, size_t *size_out)
{
    FILE *stream = fopen(path, "rb");
    long length;
    uint8_t *bytes;
    if (stream == NULL || fseek(stream, 0, SEEK_END) != 0) {
        if (stream != NULL) fclose(stream);
        return 0;
    }
    length = ftell(stream);
    if (length <= 0 || fseek(stream, 0, SEEK_SET) != 0) {
        fclose(stream);
        return 0;
    }
    bytes = malloc((size_t)length);
    if (bytes == NULL || fread(bytes, 1U, (size_t)length, stream) != (size_t)length) {
        free(bytes);
        fclose(stream);
        return 0;
    }
    fclose(stream);
    *bytes_out = bytes;
    *size_out = (size_t)length;
    return 1;
}

int main(int argc, char **argv)
{
    uint8_t *image = NULL;
    size_t image_size = 0U;
    urp_host_adapter_v1 adapter;
    urp_image_handle handle = 0U;
    uintptr_t entry_address = 0U;
    urp_entry_fn entry;
    const char *entry_argv[] = { "cfi-runtime-test", NULL };
    urp_launch_args_v1 args;
    cfi_state state = {0};
    int32_t entry_status;
    int expect_transformed = 0;

    if (argc == 3 && strcmp(argv[2], "--expect-transformed") == 0) {
        expect_transformed = 1;
    } else if (argc != 2) {
        return 2;
    }
    if (!read_image(argv[1], &image, &image_size)) return 2;

    urp_host_adapter_init(&adapter);
    adapter.context.emit_diagnostic = capture_diagnostic;
    active_state = &state;

    if (adapter.context.load_image(
            adapter.context.userdata,
            image,
            image_size,
            URP_LOAD_IMAGE_IMMUTABLE,
            &handle) != URP_STATUS_OK
        || handle == 0U
        || adapter.context.lookup_symbol(
            adapter.context.userdata,
            handle,
            "urp_entry",
            NULL,
            &entry_address) != URP_STATUS_OK) {
        free(image);
        return 3;
    }

    Dl_info info;
    if (dladdr((void *)entry_address, &info) == 0
        || info.dli_fbase == NULL
        || !find_generated_executable_range(
            image,
            image_size,
            (uintptr_t)info.dli_fbase,
            &state.target_address,
            &state.target_end,
            &state.transformed_frame_observed)) {
        (void)adapter.context.release_image(adapter.context.userdata, handle);
        free(image);
        return 3;
    }

    int image_is_transformed = state.transformed_frame_observed;
    if (image_is_transformed == 0) {
        state.target_address = 0U;
        state.target_end = 0U;
    }
    state.transformed_frame_observed = 0;
    memcpy(&entry, &entry_address, sizeof(entry));
    args.abi_version = URP_HOST_ABI_VERSION;
    args.struct_size = URP_LAUNCH_ARGS_CURRENT_SIZE;
    args.argc = 1U;
    args.argv = entry_argv;
    args.envp = NULL;
    args.image = handle;
    entry_status = entry(&adapter.context, &args);

    urp_status release_status = adapter.context.release_image(
        adapter.context.userdata,
        handle);
    active_state = NULL;
    printf(
        "schemaVersion=1 entryStatus=%d diagnosticCalls=%u frameCount=%zu "
        "transformedImage=%d transformedFrameObserved=%d releaseStatus=%d "
        "generatedRangeStart=0x%lx generatedRangeEnd=0x%lx\n",
        entry_status,
        state.diagnostic_calls,
        state.frame_count,
        image_is_transformed,
        state.transformed_frame_observed,
        release_status,
        (unsigned long)state.target_address,
        (unsigned long)state.target_end);
    free(image);

    if (entry_status != 42
        || state.diagnostic_calls != 1U
        || state.frame_count < 2U
        || release_status != URP_STATUS_OK
        || (expect_transformed
            ? (image_is_transformed == 0 || state.transformed_frame_observed == 0)
            : state.transformed_frame_observed != 0)) {
        return 4;
    }
    return 0;
}
