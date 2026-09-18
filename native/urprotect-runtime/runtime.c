#include "urp/runtime.h"

#include "sha256.h"
#include "miniz_tinfl.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

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
    const uint8_t *entry_name;
    size_t entry_name_size;
    uint32_t host_abi_version;
    uint64_t required_capabilities;
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

static int urp_u64_to_size(uint64_t value, size_t *result)
{
    if (result == NULL || value > (uint64_t)SIZE_MAX) {
        return 0;
    }
    *result = (size_t)value;
    return 1;
}

static int urp_is_valid_utf8(const uint8_t *bytes, size_t size)
{
    if (bytes == NULL) {
        return 0;
    }

    size_t index = 0U;
    while (index < size) {
        uint8_t first = bytes[index++];
        if (first <= UINT8_C(0x7F)) {
            continue;
        }

        if (first >= UINT8_C(0xC2) && first <= UINT8_C(0xDF)) {
            if (index >= size || bytes[index] < UINT8_C(0x80) || bytes[index] > UINT8_C(0xBF)) {
                return 0;
            }
            ++index;
            continue;
        }

        if (first == UINT8_C(0xE0)) {
            if (size - index < 2U
                || bytes[index] < UINT8_C(0xA0)
                || bytes[index] > UINT8_C(0xBF)
                || bytes[index + 1U] < UINT8_C(0x80)
                || bytes[index + 1U] > UINT8_C(0xBF)) {
                return 0;
            }
            index += 2U;
            continue;
        }

        if ((first >= UINT8_C(0xE1) && first <= UINT8_C(0xEC))
            || (first >= UINT8_C(0xEE) && first <= UINT8_C(0xEF))) {
            if (size - index < 2U
                || bytes[index] < UINT8_C(0x80)
                || bytes[index] > UINT8_C(0xBF)
                || bytes[index + 1U] < UINT8_C(0x80)
                || bytes[index + 1U] > UINT8_C(0xBF)) {
                return 0;
            }
            index += 2U;
            continue;
        }

        if (first == UINT8_C(0xED)) {
            if (size - index < 2U
                || bytes[index] < UINT8_C(0x80)
                || bytes[index] > UINT8_C(0x9F)
                || bytes[index + 1U] < UINT8_C(0x80)
                || bytes[index + 1U] > UINT8_C(0xBF)) {
                return 0;
            }
            index += 2U;
            continue;
        }

        if (first == UINT8_C(0xF0)) {
            if (size - index < 3U
                || bytes[index] < UINT8_C(0x90)
                || bytes[index] > UINT8_C(0xBF)
                || bytes[index + 1U] < UINT8_C(0x80)
                || bytes[index + 1U] > UINT8_C(0xBF)
                || bytes[index + 2U] < UINT8_C(0x80)
                || bytes[index + 2U] > UINT8_C(0xBF)) {
                return 0;
            }
            index += 3U;
            continue;
        }

        if (first >= UINT8_C(0xF1) && first <= UINT8_C(0xF3)) {
            if (size - index < 3U
                || bytes[index] < UINT8_C(0x80)
                || bytes[index] > UINT8_C(0xBF)
                || bytes[index + 1U] < UINT8_C(0x80)
                || bytes[index + 1U] > UINT8_C(0xBF)
                || bytes[index + 2U] < UINT8_C(0x80)
                || bytes[index + 2U] > UINT8_C(0xBF)) {
                return 0;
            }
            index += 3U;
            continue;
        }

        if (first == UINT8_C(0xF4)) {
            if (size - index < 3U
                || bytes[index] < UINT8_C(0x80)
                || bytes[index] > UINT8_C(0x8F)
                || bytes[index + 1U] < UINT8_C(0x80)
                || bytes[index + 1U] > UINT8_C(0xBF)
                || bytes[index + 2U] < UINT8_C(0x80)
                || bytes[index + 2U] > UINT8_C(0xBF)) {
                return 0;
            }
            index += 3U;
            continue;
        }

        return 0;
    }

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
    if (host == NULL
        || host->abi_version != URP_HOST_ABI_VERSION
        || host->struct_size < URP_HOST_CONTEXT_MIN_SIZE
        || (host->capabilities & URP_HOST_CAP_MANDATORY) != URP_HOST_CAP_MANDATORY
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
    if (frame == NULL || view == NULL || frame_size < URP_RUNTIME_FRAME_COMMON_HEADER_SIZE) {
        return URP_STATUS_FRAME_INVALID;
    }

    const uint8_t *header = frame;
    if (memcmp(header, urp_frame_magic, sizeof(urp_frame_magic)) != 0) {
        return URP_STATUS_FRAME_INVALID;
    }

    uint16_t version = urp_read_u16_le(header + 8U);
    uint16_t header_size = urp_read_u16_le(header + 10U);
    if (version != URP_RUNTIME_FRAME_VERSION_V1
        && version != URP_RUNTIME_FRAME_VERSION_V2) {
        return URP_STATUS_UNSUPPORTED;
    }

    uint16_t expected_header_size = version == URP_RUNTIME_FRAME_VERSION_V1
        ? URP_RUNTIME_FRAME_V1_HEADER_SIZE
        : URP_RUNTIME_FRAME_V2_HEADER_SIZE;
    if (header_size != expected_header_size
        || urp_read_u32_le(header + 12U) != URP_DEFLATE_FLAG
        || urp_read_u16_le(header + 16U) != URP_MACHINE_AARCH64
        || urp_read_u16_le(header + 18U) != URP_TYPE_DYN
        || frame_size < (size_t)header_size) {
        return URP_STATUS_FRAME_INVALID;
    }

    uint32_t host_abi_version = URP_HOST_ABI_VERSION;
    uint64_t required_capabilities = 0U;
    uint32_t entry_name_size_u32 = 0U;
    if (version == URP_RUNTIME_FRAME_VERSION_V2) {
        host_abi_version = urp_read_u32_le(
            frame + URP_RUNTIME_FRAME_V2_HOST_ABI_OFFSET);
        uint32_t reserved_before_capabilities = urp_read_u32_le(
            frame + URP_RUNTIME_FRAME_V2_RESERVED_BEFORE_CAPABILITIES_OFFSET);
        required_capabilities = urp_read_u64_le(
            frame + URP_RUNTIME_FRAME_V2_REQUIRED_CAPABILITIES_OFFSET);
        entry_name_size_u32 = urp_read_u32_le(
            frame + URP_RUNTIME_FRAME_V2_ENTRY_NAME_SIZE_OFFSET);
        uint32_t reserved_after_entry_name_size = urp_read_u32_le(
            frame + URP_RUNTIME_FRAME_V2_RESERVED_AFTER_ENTRY_NAME_SIZE_OFFSET);
        if (reserved_before_capabilities != 0U
            || reserved_after_entry_name_size != 0U) {
            return URP_STATUS_FRAME_INVALID;
        }
        if (host_abi_version != URP_HOST_ABI_VERSION
            || (required_capabilities & URP_HOST_CAP_MANDATORY)
                != URP_HOST_CAP_MANDATORY
            || (required_capabilities & ~URP_HOST_CAP_SUPPORTED) != 0U) {
            return URP_STATUS_UNSUPPORTED;
        }
        if (entry_name_size_u32 == 0U
            || entry_name_size_u32 > URP_RUNTIME_MAX_ENTRY_NAME) {
            return URP_STATUS_FRAME_INVALID;
        }
    }

    uint32_t name_size = urp_read_u32_le(header + 20U);
    uint64_t source_size = urp_read_u64_le(header + 24U);
    uint64_t encoded_size = urp_read_u64_le(header + 32U);
    uint64_t encoded_offset = urp_read_u64_le(header + 40U);
    if (name_size == 0U
        || name_size > URP_RUNTIME_MAX_ENTRY_NAME
        || source_size == 0U
        || source_size > URP_RUNTIME_MAX_SOURCE_SIZE
        || encoded_size == 0U
        || encoded_size > (uint64_t)SIZE_MAX) {
        return URP_STATUS_FRAME_INVALID;
    }

    uint64_t source_name_offset = (uint64_t)header_size;
    uint64_t encoded_offset_expected;
    if (!urp_checked_add_u64(
            source_name_offset,
            (uint64_t)name_size,
            &encoded_offset_expected)) {
        return URP_STATUS_FRAME_INVALID;
    }

    uint64_t entry_name_offset = 0U;
    if (version == URP_RUNTIME_FRAME_VERSION_V2) {
        entry_name_offset = encoded_offset_expected;
        if (!urp_checked_add_u64(
                encoded_offset_expected,
                (uint64_t)entry_name_size_u32,
                &encoded_offset_expected)) {
            return URP_STATUS_FRAME_INVALID;
        }
    }

    if (encoded_offset != encoded_offset_expected
        || encoded_offset > (uint64_t)frame_size
        || encoded_size > (uint64_t)frame_size - encoded_offset) {
        return URP_STATUS_FRAME_INVALID;
    }

    uint64_t frame_end;
    if (!urp_checked_add_u64(encoded_offset, encoded_size, &frame_end)
        || frame_end != (uint64_t)frame_size) {
        return URP_STATUS_FRAME_INVALID;
    }

    size_t source_name_offset_size;
    size_t entry_name_offset_size = 0U;
    size_t encoded_offset_size;
    size_t encoded_size_size;
    size_t name_size_size;
    if (!urp_u64_to_size(source_name_offset, &source_name_offset_size)
        || !urp_u64_to_size(encoded_offset, &encoded_offset_size)
        || !urp_u64_to_size(encoded_size, &encoded_size_size)
        || !urp_u64_to_size((uint64_t)name_size, &name_size_size)) {
        return URP_STATUS_FRAME_INVALID;
    }
    if (version == URP_RUNTIME_FRAME_VERSION_V2
        && !urp_u64_to_size(entry_name_offset, &entry_name_offset_size)) {
        return URP_STATUS_FRAME_INVALID;
    }

    const uint8_t *name = frame + source_name_offset_size;
    if (!urp_is_valid_utf8(name, name_size_size)) {
        return URP_STATUS_FRAME_INVALID;
    }
    for (size_t index = 0; index < name_size_size; ++index) {
        if (name[index] == 0U || name[index] == '/' || name[index] == '\\') {
            return URP_STATUS_FRAME_INVALID;
        }
    }
    if ((name_size_size == 1U && name[0] == '.')
        || (name_size_size == 2U && name[0] == '.' && name[1] == '.')) {
        return URP_STATUS_FRAME_INVALID;
    }

    const uint8_t *entry_name = NULL;
    size_t entry_name_size = 0U;
    if (version == URP_RUNTIME_FRAME_VERSION_V2) {
        if (!urp_u64_to_size((uint64_t)entry_name_size_u32, &entry_name_size)
            || entry_name_offset_size > frame_size
            || entry_name_size > frame_size - entry_name_offset_size) {
            return URP_STATUS_FRAME_INVALID;
        }

        entry_name = frame + entry_name_offset_size;
        if (!urp_is_valid_utf8(entry_name, entry_name_size)) {
            return URP_STATUS_FRAME_INVALID;
        }
        for (size_t index = 0; index < entry_name_size; ++index) {
            if (entry_name[index] == 0U
                || entry_name[index] == '/'
                || entry_name[index] == '\\') {
                return URP_STATUS_FRAME_INVALID;
            }
        }
        if ((entry_name_size == 1U && entry_name[0] == '.')
            || (entry_name_size == 2U
                && entry_name[0] == '.'
                && entry_name[1] == '.')) {
            return URP_STATUS_FRAME_INVALID;
        }
    }

    view->encoded = frame + encoded_offset_size;
    view->encoded_size = encoded_size_size;
    view->source_size = source_size;
    view->source_sha256 = header + 48U;
    view->encoded_sha256 = header + 80U;
    view->entry_name = entry_name;
    view->entry_name_size = entry_name_size;
    view->host_abi_version = host_abi_version;
    view->required_capabilities = required_capabilities;
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

    if (frame_view.host_abi_version != host->abi_version
        || (host->capabilities & frame_view.required_capabilities)
            != frame_view.required_capabilities) {
        urp_emit(host, URP_STATUS_HOST_INVALID, "HostContext capabilities do not satisfy the payload frame");
        return URP_STATUS_HOST_INVALID;
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

    char entry_name[URP_RUNTIME_MAX_ENTRY_NAME + 1U];
    const char *entry_symbol = URP_HOST_ENTRY_SYMBOL;
    if (frame_view.entry_name != NULL) {
        memcpy(entry_name, frame_view.entry_name, frame_view.entry_name_size);
        entry_name[frame_view.entry_name_size] = '\0';
        entry_symbol = entry_name;
    }

    uintptr_t entry_address = 0;
    status = host->lookup_symbol(
        host->userdata,
        image,
        entry_symbol,
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
