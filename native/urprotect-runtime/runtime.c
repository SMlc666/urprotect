#include "urp/runtime.h"

#include "sha256.h"
#include "miniz_tinfl.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define URP_FRAME_HEADER_SIZE 112U
#define URP_FORMAT_VERSION 1U
#define URP_DEFLATE_FLAG 1U
#define URP_MACHINE_AARCH64 183U
#define URP_TYPE_DYN 3U
#define URP_SHA256_SIZE 32U
#define URP_MAX_ARGUMENTS 4096U

static const uint8_t urp_frame_magic[8] = {'U', 'R', 'P', 'C', 'K', '0', '1', 0};

typedef struct urp_frame_view {
    const uint8_t *encoded;
    size_t encoded_size;
    uint64_t source_size;
    const uint8_t *source_sha256;
    const uint8_t *encoded_sha256;
} urp_frame_view;

static uint16_t urp_read_u16_le(const uint8_t *bytes)
{
    return (uint16_t)bytes[0]
        | (uint16_t)((uint16_t)bytes[1] << 8U);
}

static uint32_t urp_read_u32_le(const uint8_t *bytes)
{
    return (uint32_t)bytes[0]
        | ((uint32_t)bytes[1] << 8U)
        | ((uint32_t)bytes[2] << 16U)
        | ((uint32_t)bytes[3] << 24U);
}

static uint64_t urp_read_u64_le(const uint8_t *bytes)
{
    uint64_t value = 0;
    for (size_t index = 0; index < 8U; ++index) {
        value |= (uint64_t)bytes[index] << (index * 8U);
    }
    return value;
}

static int urp_checked_add_u64(uint64_t left, uint64_t right, uint64_t *result)
{
    if (right > UINT64_MAX - left) {
        return 0;
    }
    *result = left + right;
    return 1;
}

static int urp_constant_time_equal(const uint8_t *left, const uint8_t *right, size_t size)
{
    uint8_t difference = 0;
    for (size_t index = 0; index < size; ++index) {
        difference |= (uint8_t)(left[index] ^ right[index]);
    }
    return difference == 0;
}

static void urp_emit(
    const urp_host_context_v1 *host,
    urp_status status,
    const char *message)
{
    if (host != NULL
        && host->struct_size >= URP_HOST_CONTEXT_MIN_SIZE
        && (host->capabilities & URP_HOST_CAP_EMIT_DIAGNOSTIC) != 0U
        && host->emit_diagnostic != NULL) {
        uint32_t code = status < 0
            ? (uint32_t)(-(status + 1)) + 1U
            : (uint32_t)status;
        (void)host->emit_diagnostic(host->userdata, code, message);
    }
}

static urp_status urp_validate_host(const urp_host_context_v1 *host)
{
    const uint64_t required = URP_HOST_CAP_LOAD_IMAGE
        | URP_HOST_CAP_LOOKUP_SYMBOL
        | URP_HOST_CAP_RELEASE_IMAGE;
    if (host == NULL
        || host->abi_version != URP_HOST_ABI_VERSION
        || host->struct_size < URP_HOST_CONTEXT_MIN_SIZE
        || (host->capabilities & required) != required
        || host->load_image == NULL
        || host->lookup_symbol == NULL
        || host->release_image == NULL) {
        return URP_STATUS_HOST_INVALID;
    }
    return URP_STATUS_OK;
}

static urp_status urp_validate_args(const urp_launch_args_v1 *args)
{
    if (args == NULL
        || args->abi_version != URP_HOST_ABI_VERSION
        || args->struct_size < URP_LAUNCH_ARGS_MIN_SIZE
        || args->argc > URP_MAX_ARGUMENTS
        || (args->argc != 0U && args->argv == NULL)
        || args->envp == NULL) {
        return URP_STATUS_INVALID_ARGUMENT;
    }
    return URP_STATUS_OK;
}

static urp_status urp_parse_frame(
    const uint8_t *frame,
    size_t frame_size,
    urp_frame_view *view)
{
    if (frame == NULL || view == NULL || frame_size < URP_FRAME_HEADER_SIZE) {
        return URP_STATUS_FRAME_INVALID;
    }
    const uint8_t *header = frame;
    if (memcmp(header, urp_frame_magic, sizeof(urp_frame_magic)) != 0
        || urp_read_u16_le(header + 8U) != URP_FORMAT_VERSION
        || urp_read_u16_le(header + 10U) != URP_FRAME_HEADER_SIZE
        || urp_read_u32_le(header + 12U) != URP_DEFLATE_FLAG
        || urp_read_u16_le(header + 16U) != URP_MACHINE_AARCH64
        || urp_read_u16_le(header + 18U) != URP_TYPE_DYN) {
        return URP_STATUS_FRAME_INVALID;
    }

    uint32_t name_size = urp_read_u32_le(header + 20U);
    uint64_t source_size = urp_read_u64_le(header + 24U);
    uint64_t encoded_size = urp_read_u64_le(header + 32U);
    uint64_t encoded_offset = urp_read_u64_le(header + 40U);
    if (name_size == 0U
        || name_size > URP_RUNTIME_MAX_ENTRY_NAME
        || name_size > frame_size - URP_FRAME_HEADER_SIZE
        || source_size == 0U
        || source_size > URP_RUNTIME_MAX_SOURCE_SIZE
        || encoded_size == 0U
        || encoded_size > (uint64_t)SIZE_MAX
        || encoded_offset != (uint64_t)URP_FRAME_HEADER_SIZE + name_size) {
        return URP_STATUS_FRAME_INVALID;
    }

    const uint8_t *name = frame + URP_FRAME_HEADER_SIZE;
    for (uint32_t index = 0; index < name_size; ++index) {
        if (name[index] == 0U || name[index] == '/' || name[index] == '\\') {
            return URP_STATUS_FRAME_INVALID;
        }
    }

    uint64_t frame_end;
    if (!urp_checked_add_u64(encoded_offset, encoded_size, &frame_end)
        || frame_end != (uint64_t)frame_size) {
        return URP_STATUS_FRAME_INVALID;
    }

    view->encoded = frame + (size_t)encoded_offset;
    view->encoded_size = (size_t)encoded_size;
    view->source_size = source_size;
    view->source_sha256 = header + 48U;
    view->encoded_sha256 = header + 80U;
    return URP_STATUS_OK;
}

static urp_status urp_decode_frame(
    const urp_frame_view *frame,
    uint8_t **source_out,
    size_t *source_size_out)
{
    if (frame == NULL || source_out == NULL || source_size_out == NULL
        || frame->source_size > (uint64_t)SIZE_MAX) {
        return URP_STATUS_FRAME_INVALID;
    }

    uint8_t encoded_digest[URP_SHA256_SIZE];
    urp_sha256_context encoded_context;
    urp_sha256_init(&encoded_context);
    urp_sha256_update(&encoded_context, frame->encoded, frame->encoded_size);
    urp_sha256_final(&encoded_context, encoded_digest);
    if (!urp_constant_time_equal(encoded_digest, frame->encoded_sha256, URP_SHA256_SIZE)) {
        return URP_STATUS_INTEGRITY_FAILURE;
    }

    size_t source_size = (size_t)frame->source_size;
    uint8_t *source = (uint8_t *)malloc(source_size);
    if (source == NULL) {
        return URP_STATUS_LOAD_FAILED;
    }

    tinfl_decompressor decompressor;
    tinfl_init(&decompressor);
    size_t input_size = frame->encoded_size;
    size_t output_size = source_size;
    tinfl_status status = tinfl_decompress(
        &decompressor,
        frame->encoded,
        &input_size,
        source,
        source,
        &output_size,
        TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
    if (status != TINFL_STATUS_DONE
        || input_size != frame->encoded_size
        || output_size != source_size) {
        free(source);
        return URP_STATUS_FRAME_INVALID;
    }

    uint8_t source_digest[URP_SHA256_SIZE];
    urp_sha256_context source_context;
    urp_sha256_init(&source_context);
    urp_sha256_update(&source_context, source, source_size);
    urp_sha256_final(&source_context, source_digest);
    if (!urp_constant_time_equal(source_digest, frame->source_sha256, URP_SHA256_SIZE)) {
        free(source);
        return URP_STATUS_INTEGRITY_FAILURE;
    }

    *source_out = source;
    *source_size_out = source_size;
    return URP_STATUS_OK;
}

urp_status urp_runtime_execute_frame(
    const urp_host_context_v1 *host,
    const uint8_t *frame,
    size_t frame_size,
    const urp_launch_args_v1 *args)
{
    urp_status status = urp_validate_host(host);
    if (status != URP_STATUS_OK) {
        return status;
    }
    status = urp_validate_args(args);
    if (status != URP_STATUS_OK) {
        urp_emit(host, status, "HostContext launch arguments are invalid");
        return status;
    }

    urp_frame_view frame_view;
    status = urp_parse_frame(frame, frame_size, &frame_view);
    if (status != URP_STATUS_OK) {
        urp_emit(host, status, "HostContext payload frame is invalid");
        return status;
    }

    uint8_t *source = NULL;
    size_t source_size = 0;
    status = urp_decode_frame(&frame_view, &source, &source_size);
    if (status != URP_STATUS_OK) {
        urp_emit(host, status, "HostContext payload integrity or compression check failed");
        return status;
    }

    urp_image_handle image = 0;
    status = host->load_image(
        host->userdata,
        source,
        source_size,
        URP_LOAD_IMAGE_IMMUTABLE,
        &image);
    free(source);
    if (status != URP_STATUS_OK) {
        urp_emit(host, status, "HostContext host image loading failed");
        return status;
    }

    uintptr_t entry_address = 0;
    status = host->lookup_symbol(
        host->userdata,
        image,
        URP_HOST_ENTRY_SYMBOL,
        NULL,
        &entry_address);
    if (status == URP_STATUS_OK && entry_address == 0U) {
        status = URP_STATUS_SYMBOL_NOT_FOUND;
    }

    urp_status entry_status = status;
    if (status == URP_STATUS_OK) {
        urp_entry_fn entry = NULL;
        if (sizeof(entry) != sizeof(entry_address)) {
            entry_status = URP_STATUS_UNSUPPORTED;
        } else {
            memcpy(&entry, &entry_address, sizeof(entry));
            entry_status = entry(host, args);
        }
    }

    urp_status release_status = host->release_image(host->userdata, image);
    if (entry_status == URP_STATUS_OK && release_status != URP_STATUS_OK) {
        entry_status = release_status;
    }
    if (entry_status < URP_STATUS_OK) {
        urp_emit(host, entry_status, "HostContext entry dispatch failed");
    }
    return entry_status;
}
