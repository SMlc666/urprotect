#include "urp/host_context.h"
#include "urp/host_adapter.h"
#include "urp/runtime.h"
#include "sha256.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

_Static_assert(offsetof(urp_host_context_v1, abi_version) == 0, "ABI version must be first");
_Static_assert(offsetof(urp_host_context_v1, struct_size) == 4, "ABI size must follow version");
_Static_assert(offsetof(urp_host_context_v1, capabilities) == 8, "Capabilities offset changed");
_Static_assert(offsetof(urp_launch_args_v1, argc) == 8, "Argument count offset changed");

#define FIXTURE_ELF_HEADER_SIZE 64U
#define FIXTURE_ELF_PROGRAM_HEADER_SIZE 56U
#define FIXTURE_ELF_DYNAMIC_ENTRY_SIZE 16U
#define FIXTURE_PT_LOAD 1U
#define FIXTURE_PT_DYNAMIC 2U
#define FIXTURE_PT_TLS 7U
#define FIXTURE_PT_GNU_EH_FRAME 0x6474e550U
#define FIXTURE_PT_GNU_PROPERTY 0x6474e553U
#define FIXTURE_PT_GNU_STACK 0x6474e551U
#define FIXTURE_PT_GNU_RELRO 0x6474e552U
#define FIXTURE_PF_X 1U
#define FIXTURE_DT_NEEDED 1U
#define FIXTURE_DT_INIT 12U
#define FIXTURE_DT_FINI 13U
#define FIXTURE_DT_RPATH 15U
#define FIXTURE_DT_INIT_ARRAY 25U
#define FIXTURE_DT_FINI_ARRAY 26U
#define FIXTURE_DT_INIT_ARRAYSZ 27U
#define FIXTURE_DT_FINI_ARRAYSZ 28U
#define FIXTURE_DT_RUNPATH 29U
#define FIXTURE_DT_PREINIT_ARRAY 32U
#define FIXTURE_DT_PREINIT_ARRAYSZ 33U
#define FIXTURE_DT_RELA 7U
#define FIXTURE_DT_RELASZ 8U
#define FIXTURE_DT_RELAENT 9U
#define FIXTURE_DT_RELR 36U
#define FIXTURE_DT_RELRSZ 35U
#define FIXTURE_DT_RELRENT 37U
#define FIXTURE_DT_FLAGS 30U

static const uint8_t fixture_frame[] = {
    0x55, 0x52, 0x50, 0x43, 0x4b, 0x30, 0x31, 0x00, 0x01, 0x00, 0x70, 0x00,
    0x01, 0x00, 0x00, 0x00, 0xb7, 0x00, 0x03, 0x00, 0x1a, 0x00, 0x00, 0x00,
    0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x8a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x61, 0x2f, 0x35, 0x55, 0x0d, 0x6c, 0xad, 0x74, 0x5a, 0xc6, 0x7e, 0x9f,
    0xab, 0xe3, 0x40, 0xb5, 0x06, 0xa5, 0x7b, 0x0a, 0x4f, 0xae, 0xa0, 0x44,
    0x76, 0xfd, 0xbd, 0x13, 0x00, 0xca, 0xee, 0x1e, 0x8c, 0xe0, 0x3f, 0x9d,
    0x41, 0xbb, 0x8d, 0x41, 0x42, 0xf6, 0x8e, 0x29, 0xa8, 0xe0, 0xe6, 0xa0,
    0xe3, 0x55, 0xbd, 0xa0, 0xf9, 0xe6, 0xad, 0xe1, 0x11, 0x5e, 0xa7, 0x49,
    0x81, 0x36, 0xc6, 0x3f, 0x68, 0x6f, 0x73, 0x74, 0x2d, 0x63, 0x6f, 0x6e,
    0x74, 0x65, 0x78, 0x74, 0x2d, 0x65, 0x6e, 0x74, 0x72, 0x79, 0x2d, 0x66,
    0x69, 0x78, 0x74, 0x75, 0x72, 0x65, 0xcb, 0xc8, 0x2f, 0x2e, 0xd1, 0x4d,
    0xce, 0xcf, 0x2b, 0x49, 0xad, 0x28, 0xd1, 0x4d, 0xcd, 0x2b, 0x29, 0xaa,
    0xd4, 0x4d, 0xcb, 0xac, 0x28, 0x29, 0x2d, 0x4a, 0xe5, 0x02, 0x00,
};

typedef struct fixture_state {
    int loaded;
    int immutable;
    int looked_up;
    int entry_called;
    int released;
    int diagnostics;
    const char *expected_entry_name;
} fixture_state;

typedef struct fixture_dynamic_rejection {
    uint64_t tag;
    const char *message;
} fixture_dynamic_rejection;

static int32_t fixture_entry(
    const urp_host_context_v1 *host,
    const urp_launch_args_v1 *args)
{
    fixture_state *state = (fixture_state *)host->userdata;
    if (args->argc != 1U || args->argv == NULL || strcmp(args->argv[0], "fixture") != 0) {
        return 19;
    }
    state->entry_called = 1;
    return 17;
}

static urp_status fixture_load_image(
    void *userdata,
    const void *bytes,
    size_t size,
    uint32_t flags,
    urp_image_handle *out_handle)
{
    fixture_state *state = (fixture_state *)userdata;
    static const uint8_t expected[] = "host-context-entry-fixture\n";
    if (bytes == NULL || size != sizeof(expected) - 1U || out_handle == NULL
        || memcmp(bytes, expected, sizeof(expected) - 1U) != 0) {
        return URP_STATUS_LOAD_FAILED;
    }
    state->loaded = 1;
    state->immutable = flags == URP_LOAD_IMAGE_IMMUTABLE;
    *out_handle = 1U;
    return URP_STATUS_OK;
}

static urp_status fixture_lookup_symbol(
    void *userdata,
    urp_image_handle image,
    const char *name,
    const char *version,
    uintptr_t *out_address)
{
    fixture_state *state = (fixture_state *)userdata;
    urp_entry_fn entry = fixture_entry;
    const char *expected_name = state->expected_entry_name != NULL
        ? state->expected_entry_name
        : URP_HOST_ENTRY_SYMBOL;
    if (image != 1U || name == NULL || strcmp(name, expected_name) != 0
        || version != NULL || out_address == NULL
        || sizeof(*out_address) != sizeof(entry)) {
        return URP_STATUS_SYMBOL_NOT_FOUND;
    }
    state->looked_up = 1;
    memcpy(out_address, &entry, sizeof(entry));
    return URP_STATUS_OK;
}

static urp_status fixture_release_image(void *userdata, urp_image_handle image)
{
    fixture_state *state = (fixture_state *)userdata;
    if (image != 1U) {
        return URP_STATUS_INVALID_ARGUMENT;
    }
    state->released = 1;
    return URP_STATUS_OK;
}

static urp_status fixture_emit_diagnostic(void *userdata, uint32_t code, const char *message)
{
    fixture_state *state = (fixture_state *)userdata;
    if (code == 0U || message == NULL) {
        return URP_STATUS_INVALID_ARGUMENT;
    }
    state->diagnostics++;
    return URP_STATUS_OK;
}

static int fixture_expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "HostContext self-test: %s\n", message);
        return 0;
    }
    return 1;
}

static void fixture_write_u16_le(uint8_t *destination, uint16_t value)
{
    destination[0] = (uint8_t)value;
    destination[1] = (uint8_t)(value >> 8U);
}

static void fixture_write_u32_le(uint8_t *destination, uint32_t value)
{
    for (size_t index = 0; index < 4U; ++index) {
        destination[index] = (uint8_t)(value >> (index * 8U));
    }
}

static void fixture_write_u64_le(uint8_t *destination, uint64_t value)
{
    for (size_t index = 0; index < 8U; ++index) {
        destination[index] = (uint8_t)(value >> (index * 8U));
    }
}

static uint16_t fixture_read_u16_le(const uint8_t *source)
{
    return (uint16_t)source[0]
        | (uint16_t)((uint16_t)source[1] << 8U);
}

static uint32_t fixture_read_u32_le(const uint8_t *source)
{
    return (uint32_t)source[0]
        | ((uint32_t)source[1] << 8U)
        | ((uint32_t)source[2] << 16U)
        | ((uint32_t)source[3] << 24U);
}

static uint64_t fixture_read_u64_le(const uint8_t *source)
{
    uint64_t value = 0U;
    for (size_t index = 0; index < 8U; ++index) {
        value |= (uint64_t)source[index] << (index * 8U);
    }
    return value;
}

static int fixture_range_in_file(
    size_t file_size,
    uint64_t offset,
    uint64_t length,
    size_t *offset_out,
    size_t *length_out)
{
    if (offset > (uint64_t)SIZE_MAX
        || length > (uint64_t)SIZE_MAX
        || offset > (uint64_t)file_size
        || length > (uint64_t)file_size - offset) {
        return 0;
    }
    if (offset_out != NULL) {
        *offset_out = (size_t)offset;
    }
    if (length_out != NULL) {
        *length_out = (size_t)length;
    }
    return 1;
}

static int fixture_range_within(
    uint64_t outer_offset,
    uint64_t outer_size,
    uint64_t inner_offset,
    uint64_t inner_size)
{
    if (outer_offset > UINT64_MAX - outer_size
        || inner_offset > UINT64_MAX - inner_size
        || inner_offset < outer_offset) {
        return 0;
    }

    uint64_t delta = inner_offset - outer_offset;
    return delta <= outer_size && inner_size <= outer_size - delta;
}

static int fixture_checked_add_u64(uint64_t left, uint64_t right, uint64_t *result)
{
    if (result == NULL || right > UINT64_MAX - left) {
        return 0;
    }
    *result = left + right;
    return 1;
}

static int fixture_checked_mul_u64(uint64_t left, uint64_t right, uint64_t *result)
{
    if (result == NULL || (left != 0U && right > UINT64_MAX / left)) {
        return 0;
    }
    *result = left * right;
    return 1;
}

static int fixture_find_program_header(
    const uint8_t *source,
    size_t source_size,
    uint32_t wanted_type,
    const uint8_t **header_out)
{
    if (source == NULL || header_out == NULL || source_size < FIXTURE_ELF_HEADER_SIZE
        || fixture_read_u16_le(source + 54U) != FIXTURE_ELF_PROGRAM_HEADER_SIZE) {
        return 0;
    }

    uint64_t program_header_offset = fixture_read_u64_le(source + 32U);
    uint16_t program_header_count = fixture_read_u16_le(source + 56U);
    for (uint16_t index = 0; index < program_header_count; ++index) {
        uint64_t index_offset;
        uint64_t header_offset_value;
        if (!fixture_checked_mul_u64(
                (uint64_t)index,
                FIXTURE_ELF_PROGRAM_HEADER_SIZE,
                &index_offset)
            || !fixture_checked_add_u64(
                program_header_offset,
                index_offset,
                &header_offset_value)) {
            return 0;
        }

        size_t header_offset;
        if (!fixture_range_in_file(
                source_size,
                header_offset_value,
                FIXTURE_ELF_PROGRAM_HEADER_SIZE,
                &header_offset,
                NULL)) {
            return 0;
        }

        const uint8_t *header = source + header_offset;
        if (fixture_read_u32_le(header) == wanted_type) {
            *header_out = header;
            return 1;
        }
    }
    return 0;
}

static int fixture_find_dynamic_segment(
    const uint8_t *source,
    size_t source_size,
    size_t *offset_out,
    size_t *size_out)
{
    const uint8_t *header;
    if (!fixture_find_program_header(
            source,
            source_size,
            FIXTURE_PT_DYNAMIC,
            &header)) {
        return 0;
    }
    return fixture_range_in_file(
        source_size,
        fixture_read_u64_le(header + 8U),
        fixture_read_u64_le(header + 32U),
        offset_out,
        size_out);
}

static int fixture_find_dynamic_entry(
    const uint8_t *source,
    size_t source_size,
    uint64_t wanted_tag,
    size_t *tag_offset_out,
    size_t *value_offset_out)
{
    size_t dynamic_offset;
    size_t dynamic_size;
    if (!fixture_find_dynamic_segment(
            source,
            source_size,
            &dynamic_offset,
            &dynamic_size)
        || dynamic_size % FIXTURE_ELF_DYNAMIC_ENTRY_SIZE != 0U) {
        return 0;
    }

    for (size_t offset = 0; offset < dynamic_size; offset += FIXTURE_ELF_DYNAMIC_ENTRY_SIZE) {
        const uint8_t *entry = source + dynamic_offset + offset;
        uint64_t tag = fixture_read_u64_le(entry);
        if (tag == 0U) {
            return 0;
        }
        if (tag == wanted_tag) {
            if (tag_offset_out != NULL) {
                *tag_offset_out = dynamic_offset + offset;
            }
            if (value_offset_out != NULL) {
                *value_offset_out = dynamic_offset + offset + 8U;
            }
            return 1;
        }
    }
    return 0;
}

static int fixture_find_dynamic_terminator(
    const uint8_t *source,
    size_t source_size,
    size_t *tag_offset_out)
{
    size_t dynamic_offset;
    size_t dynamic_size;
    if (!fixture_find_dynamic_segment(
            source,
            source_size,
            &dynamic_offset,
            &dynamic_size)
        || dynamic_size % FIXTURE_ELF_DYNAMIC_ENTRY_SIZE != 0U) {
        return 0;
    }

    for (size_t offset = 0; offset < dynamic_size; offset += FIXTURE_ELF_DYNAMIC_ENTRY_SIZE) {
        size_t tag_offset = dynamic_offset + offset;
        if (fixture_read_u64_le(source + tag_offset) == 0U) {
            if (tag_offset_out != NULL) {
                *tag_offset_out = tag_offset;
            }
            return 1;
        }
    }
    return 0;
}

static int fixture_read_file(const char *path, uint8_t **bytes_out, size_t *size_out)
{
    if (path == NULL || bytes_out == NULL || size_out == NULL) {
        return 0;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return 0;
    }
    struct stat metadata;
    if (fstat(fd, &metadata) != 0
        || metadata.st_size <= 0
        || (uintmax_t)metadata.st_size > (uintmax_t)SIZE_MAX) {
        (void)close(fd);
        return 0;
    }

    size_t size = (size_t)metadata.st_size;
    uint8_t *bytes = (uint8_t *)malloc(size);
    if (bytes == NULL) {
        (void)close(fd);
        return 0;
    }

    size_t offset = 0U;
    while (offset < size) {
        ssize_t read_size = read(fd, bytes + offset, size - offset);
        if (read_size < 0 && errno == EINTR) {
            continue;
        }
        if (read_size <= 0) {
            free(bytes);
            (void)close(fd);
            return 0;
        }
        offset += (size_t)read_size;
    }
    if (close(fd) != 0) {
        free(bytes);
        return 0;
    }

    *bytes_out = bytes;
    *size_out = size;
    return 1;
}

static int fixture_make_stored_deflate(
    const uint8_t *source,
    size_t source_size,
    uint8_t **encoded_out,
    size_t *encoded_size_out)
{
    if (source == NULL || source_size == 0U || encoded_out == NULL || encoded_size_out == NULL) {
        return 0;
    }

    size_t block_count = source_size / UINT16_MAX;
    if (source_size % UINT16_MAX != 0U) {
        ++block_count;
    }
    if (block_count > (SIZE_MAX - source_size) / 5U) {
        return 0;
    }
    size_t encoded_size = source_size + block_count * 5U;
    uint8_t *encoded = (uint8_t *)malloc(encoded_size);
    if (encoded == NULL) {
        return 0;
    }

    size_t source_offset = 0U;
    size_t encoded_offset = 0U;
    while (source_offset < source_size) {
        size_t remaining = source_size - source_offset;
        uint16_t block_size = remaining > UINT16_MAX
            ? UINT16_MAX
            : (uint16_t)remaining;
        uint16_t inverse_size = (uint16_t)~block_size;
        encoded[encoded_offset++] = remaining <= UINT16_MAX ? 1U : 0U;
        encoded[encoded_offset++] = (uint8_t)block_size;
        encoded[encoded_offset++] = (uint8_t)(block_size >> 8U);
        encoded[encoded_offset++] = (uint8_t)inverse_size;
        encoded[encoded_offset++] = (uint8_t)(inverse_size >> 8U);
        memcpy(encoded + encoded_offset, source + source_offset, block_size);
        encoded_offset += block_size;
        source_offset += block_size;
    }

    *encoded_out = encoded;
    *encoded_size_out = encoded_size;
    return 1;
}

static int fixture_make_frame_versioned(
    const uint8_t *source,
    size_t source_size,
    const char *source_name,
    const char *entry_name,
    uint8_t **frame_out,
    size_t *frame_size_out)
{
    if (source == NULL || source_size == 0U || source_name == NULL
        || frame_out == NULL || frame_size_out == NULL) {
        return 0;
    }

    size_t source_name_size = strlen(source_name);
    if (source_name_size == 0U || source_name_size > UINT32_MAX) {
        return 0;
    }

    int is_v2 = entry_name != NULL;
    size_t entry_name_size = is_v2 ? strlen(entry_name) : 0U;
    if (is_v2 && (entry_name_size == 0U || entry_name_size > UINT32_MAX)) {
        return 0;
    }

    size_t header_size = is_v2
        ? (size_t)URP_RUNTIME_FRAME_V2_HEADER_SIZE
        : (size_t)URP_RUNTIME_FRAME_V1_HEADER_SIZE;
    if (header_size > SIZE_MAX - source_name_size) {
        return 0;
    }
    size_t encoded_offset = header_size + source_name_size;
    if (entry_name_size > SIZE_MAX - encoded_offset) {
        return 0;
    }
    encoded_offset += entry_name_size;

    uint8_t *encoded = NULL;
    size_t encoded_size = 0U;
    if (!fixture_make_stored_deflate(source, source_size, &encoded, &encoded_size)
        || encoded_size > SIZE_MAX - encoded_offset) {
        free(encoded);
        return 0;
    }

    size_t frame_size = encoded_offset + encoded_size;
    uint8_t *frame = (uint8_t *)calloc(1U, frame_size);
    if (frame == NULL) {
        free(encoded);
        return 0;
    }

    static const uint8_t magic[] = {'U', 'R', 'P', 'C', 'K', '0', '1', 0};
    memcpy(frame, magic, sizeof(magic));
    fixture_write_u16_le(
        frame + 8U,
        is_v2 ? URP_RUNTIME_FRAME_VERSION_V2 : URP_RUNTIME_FRAME_VERSION_V1);
    fixture_write_u16_le(frame + 10U, (uint16_t)header_size);
    fixture_write_u32_le(frame + 12U, 1U);
    fixture_write_u16_le(frame + 16U, 183U);
    fixture_write_u16_le(frame + 18U, 3U);
    fixture_write_u32_le(frame + 20U, (uint32_t)source_name_size);
    fixture_write_u64_le(frame + 24U, (uint64_t)source_size);
    fixture_write_u64_le(frame + 32U, (uint64_t)encoded_size);
    fixture_write_u64_le(frame + 40U, (uint64_t)encoded_offset);

    if (is_v2) {
        fixture_write_u32_le(frame + URP_RUNTIME_FRAME_V2_HOST_ABI_OFFSET, URP_HOST_ABI_VERSION);
        fixture_write_u64_le(
            frame + URP_RUNTIME_FRAME_V2_REQUIRED_CAPABILITIES_OFFSET,
            URP_HOST_CAP_MANDATORY);
        fixture_write_u32_le(
            frame + URP_RUNTIME_FRAME_V2_ENTRY_NAME_SIZE_OFFSET,
            (uint32_t)entry_name_size);
    }

    urp_sha256_context source_context;
    uint8_t source_hash[32];
    urp_sha256_init(&source_context);
    urp_sha256_update(&source_context, source, source_size);
    urp_sha256_final(&source_context, source_hash);
    memcpy(frame + 48U, source_hash, sizeof(source_hash));

    urp_sha256_context encoded_context;
    uint8_t encoded_hash[32];
    urp_sha256_init(&encoded_context);
    urp_sha256_update(&encoded_context, encoded, encoded_size);
    urp_sha256_final(&encoded_context, encoded_hash);
    memcpy(frame + 80U, encoded_hash, sizeof(encoded_hash));

    memcpy(frame + header_size, source_name, source_name_size);
    if (is_v2) {
        memcpy(frame + header_size + source_name_size, entry_name, entry_name_size);
    }
    memcpy(frame + encoded_offset, encoded, encoded_size);
    free(encoded);
    *frame_out = frame;
    *frame_size_out = frame_size;
    return 1;
}

static int fixture_make_frame(
    const uint8_t *source,
    size_t source_size,
    const char *source_name,
    uint8_t **frame_out,
    size_t *frame_size_out)
{
    return fixture_make_frame_versioned(
        source,
        source_size,
        source_name,
        NULL,
        frame_out,
        frame_size_out);
}

static int fixture_make_v2_frame(
    const uint8_t *source,
    size_t source_size,
    const char *source_name,
    const char *entry_name,
    uint8_t **frame_out,
    size_t *frame_size_out)
{
    return fixture_make_frame_versioned(
        source,
        source_size,
        source_name,
        entry_name,
        frame_out,
        frame_size_out);
}

static int fixture_run_real_adapter(const char *fixture_path)
{
    uint8_t *source = NULL;
    size_t source_size = 0U;
    if (!fixture_read_file(fixture_path, &source, &source_size)) {
        return fixture_expect(0, "could not read the AArch64 entry fixture");
    }
    if (!fixture_expect(source_size >= 64U, "entry fixture ELF header is truncated")) {
        free(source);
        return 0;
    }

    const uint8_t *gnu_stack_header;
    if (!fixture_expect(
            fixture_find_program_header(
                source,
                source_size,
                FIXTURE_PT_GNU_STACK,
                &gnu_stack_header),
            "entry fixture has no PT_GNU_STACK program header")) {
        free(source);
        return 0;
    }
    uint32_t gnu_stack_flags = fixture_read_u32_le(gnu_stack_header + 4U);
    if (!fixture_expect(
            (gnu_stack_flags & FIXTURE_PF_X) == 0U,
            "entry fixture PT_GNU_STACK is executable")) {
        free(source);
        return 0;
    }

    const uint8_t *relro_header;
    if (!fixture_expect(
            fixture_find_program_header(
                source,
                source_size,
                FIXTURE_PT_GNU_RELRO,
                &relro_header),
            "entry fixture has no bounded PT_GNU_RELRO program header")) {
        free(source);
        return 0;
    }
    uint64_t relro_file_offset = fixture_read_u64_le(relro_header + 8U);
    uint64_t relro_file_size = fixture_read_u64_le(relro_header + 32U);
    uint64_t relro_memory_size = fixture_read_u64_le(relro_header + 40U);
    if (!fixture_expect(
            relro_file_size > 0U,
            "entry fixture PT_GNU_RELRO has an empty file-backed range")) {
        free(source);
        return 0;
    }
    if (!fixture_expect(
            relro_memory_size >= relro_file_size,
            "entry fixture PT_GNU_RELRO has p_memsz smaller than p_filesz")) {
        free(source);
        return 0;
    }
    size_t relro_file_offset_as_size;
    size_t relro_file_size_as_size;
    if (!fixture_expect(
            fixture_range_in_file(
                source_size,
                relro_file_offset,
                relro_file_size,
                &relro_file_offset_as_size,
                &relro_file_size_as_size),
            "entry fixture PT_GNU_RELRO file-backed range is outside the image")) {
        free(source);
        return 0;
    }

    uint8_t *frame = NULL;
    size_t frame_size = 0U;
    int made_frame = fixture_make_frame(
        source,
        source_size,
        "host-context-entry-fixture.so",
        &frame,
        &frame_size);
    if (!fixture_expect(made_frame, "could not construct the real adapter frame")) {
        free(source);
        return 0;
    }

    urp_host_adapter_v1 adapter;
    urp_host_adapter_init(&adapter);
    const char *launch_argv[] = {"fixture", NULL};
    const char *launch_envp[] = {NULL};
    urp_launch_args_v1 args = {
        .abi_version = URP_HOST_ABI_VERSION,
        .struct_size = sizeof(urp_launch_args_v1),
        .argc = 1U,
        .argv = launch_argv,
        .envp = launch_envp,
    };
    urp_status status = urp_runtime_execute_frame(
        &adapter.context,
        frame,
        frame_size,
        &args);
    free(frame);
    if (!fixture_expect(
            status == 23,
            "the PT_GNU_RELRO AArch64 HostContext entry was not invoked with status 23")) {
        free(source);
        return 0;
    }

    size_t gnu_stack_header_offset = (size_t)(gnu_stack_header - source);
    uint8_t *executable_stack_image = (uint8_t *)malloc(source_size);
    if (!fixture_expect(
            executable_stack_image != NULL,
            "could not allocate the executable-stack HostContext fixture")) {
        free(source);
        return 0;
    }
    memcpy(executable_stack_image, source, source_size);
    fixture_write_u32_le(
        executable_stack_image + gnu_stack_header_offset + 4U,
        gnu_stack_flags | FIXTURE_PF_X);
    urp_image_handle rejected_handle = 0U;
    status = adapter.context.load_image(
        adapter.context.userdata,
        executable_stack_image,
        source_size,
        URP_LOAD_IMAGE_IMMUTABLE,
        &rejected_handle);
    free(executable_stack_image);
    if (!fixture_expect(
            status == URP_STATUS_UNSUPPORTED && rejected_handle == 0U,
            "an executable PT_GNU_STACK was accepted or returned a handle")) {
        free(source);
        return 0;
    }

    uint8_t *sectionless_image = (uint8_t *)malloc(source_size);
    if (!fixture_expect(
            sectionless_image != NULL,
            "could not allocate the sectionless HostContext fixture")) {
        free(source);
        return 0;
    }
    memcpy(sectionless_image, source, source_size);
    fixture_write_u64_le(sectionless_image + 40U, 0U);
    fixture_write_u16_le(sectionless_image + 58U, 0U);
    fixture_write_u16_le(sectionless_image + 60U, 0U);
    fixture_write_u16_le(sectionless_image + 62U, 0U);
    uint8_t *sectionless_frame = NULL;
    size_t sectionless_frame_size = 0U;
    int made_sectionless_frame = fixture_make_frame(
        sectionless_image,
        source_size,
        "host-context-sectionless-fixture.so",
        &sectionless_frame,
        &sectionless_frame_size);
    if (!fixture_expect(
            made_sectionless_frame,
            "could not construct the sectionless HostContext frame")) {
        free(sectionless_image);
        free(source);
        return 0;
    }
    status = urp_runtime_execute_frame(
        &adapter.context,
        sectionless_frame,
        sectionless_frame_size,
        &args);
    free(sectionless_frame);
    free(sectionless_image);
    if (!fixture_expect(
            status == 23,
            "a sectionless HostContext image was not dispatched")) {
        free(source);
        return 0;
    }
    size_t rela_tag_offset;
    size_t rela_value_offset;
    size_t rela_size_tag_offset;
    size_t rela_size_value_offset;
    size_t rela_ent_tag_offset;
    size_t rela_ent_value_offset;
    if (!fixture_expect(
            fixture_find_dynamic_entry(
                source,
                source_size,
                FIXTURE_DT_RELA,
                &rela_tag_offset,
                &rela_value_offset)
            && fixture_find_dynamic_entry(
                source,
                source_size,
                FIXTURE_DT_RELASZ,
                &rela_size_tag_offset,
                &rela_size_value_offset)
            && fixture_find_dynamic_entry(
                source,
                source_size,
                FIXTURE_DT_RELAENT,
                &rela_ent_tag_offset,
                &rela_ent_value_offset),
            "the entry fixture does not expose the expected RELA metadata")) {
        free(source);
        return 0;
    }

    uint8_t *invalid_rela = (uint8_t *)malloc(source_size);
    if (!fixture_expect(invalid_rela != NULL, "could not allocate the invalid RELA fixture")) {
        free(source);
        return 0;
    }
    memcpy(invalid_rela, source, source_size);
    uint64_t rela_offset = fixture_read_u64_le(source + rela_value_offset);
    if (!fixture_expect(
            fixture_range_in_file(source_size, rela_offset, 24U, NULL, NULL),
            "the entry fixture RELA range is outside the source")) {
        free(invalid_rela);
        free(source);
        return 0;
    }
    fixture_write_u64_le(invalid_rela + (size_t)rela_offset, 0x100U);
    rejected_handle = 0U;
    status = adapter.context.load_image(
        adapter.context.userdata,
        invalid_rela,
        source_size,
        URP_LOAD_IMAGE_IMMUTABLE,
        &rejected_handle);
    free(invalid_rela);
    if (!fixture_expect(
            status == URP_STATUS_UNSUPPORTED,
            "an invalid RELA target was not rejected before loading")) {
        free(source);
        return 0;
    }

    size_t dynamic_offset;
    size_t dynamic_size;
    if (!fixture_expect(
            fixture_find_dynamic_segment(source, source_size, &dynamic_offset, &dynamic_size)
                && dynamic_size >= FIXTURE_ELF_DYNAMIC_ENTRY_SIZE,
            "the entry fixture does not expose a bounded dynamic segment")) {
        free(source);
        return 0;
    }
    uint8_t *unterminated_dynamic = (uint8_t *)malloc(source_size);
    if (!fixture_expect(
            unterminated_dynamic != NULL,
            "could not allocate the unterminated dynamic fixture")) {
        free(source);
        return 0;
    }
    memcpy(unterminated_dynamic, source, source_size);
    for (size_t offset = 0; offset < dynamic_size; offset += FIXTURE_ELF_DYNAMIC_ENTRY_SIZE) {
        uint8_t *entry = unterminated_dynamic + dynamic_offset + offset;
        if (fixture_read_u64_le(entry) == 0U) {
            fixture_write_u64_le(entry, UINT64_C(0xDEAD) + (uint64_t)offset);
        }
    }
    rejected_handle = 0U;
    status = adapter.context.load_image(
        adapter.context.userdata,
        unterminated_dynamic,
        source_size,
        URP_LOAD_IMAGE_IMMUTABLE,
        &rejected_handle);
    free(unterminated_dynamic);
    if (!fixture_expect(
            status == URP_STATUS_LOAD_FAILED,
            "an unterminated dynamic segment was accepted")) {
        free(source);
        return 0;
    }

    uint8_t *relr_image = (uint8_t *)malloc(source_size);
    if (!fixture_expect(relr_image != NULL, "could not allocate the RELR fixture")) {
        free(source);
        return 0;
    }
    memcpy(relr_image, source, source_size);
    fixture_write_u64_le(relr_image + rela_tag_offset, FIXTURE_DT_RELR);
    fixture_write_u64_le(relr_image + rela_size_tag_offset, FIXTURE_DT_RELRSZ);
    fixture_write_u64_le(relr_image + rela_ent_tag_offset, FIXTURE_DT_RELRENT);
    fixture_write_u64_le(relr_image + rela_size_value_offset, sizeof(uint64_t));
    fixture_write_u64_le(relr_image + rela_ent_value_offset, sizeof(uint64_t));
    uint8_t *relr_frame = NULL;
    size_t relr_frame_size = 0U;
    int made_relr_frame = fixture_make_frame(
        relr_image,
        source_size,
        "host-context-relr-fixture.so",
        &relr_frame,
        &relr_frame_size);
    if (!fixture_expect(made_relr_frame, "could not construct the RELR fixture frame")) {
        free(relr_image);
        free(source);
        return 0;
    }
    status = urp_runtime_execute_frame(
        &adapter.context,
        relr_frame,
        relr_frame_size,
        &args);
    free(relr_frame);
    free(relr_image);
    if (!fixture_expect(status == 23, "a valid RELR image was not dispatched")) {
        free(source);
        return 0;
    }

    size_t flags_value_offset;
    size_t dynamic_terminator_offset;
    if (!fixture_expect(
            fixture_find_dynamic_entry(
                source,
                source_size,
                FIXTURE_DT_FLAGS,
                NULL,
                &flags_value_offset)
            && fixture_find_dynamic_terminator(
                source,
                source_size,
                &dynamic_terminator_offset),
            "the entry fixture does not expose the expected dynamic metadata")) {
        free(source);
        return 0;
    }
    if (!fixture_expect(
            dynamic_terminator_offset <= source_size
                && sizeof(uint64_t) <= source_size - dynamic_terminator_offset
                && fixture_read_u64_le(source + dynamic_terminator_offset) == 0U,
            "the dynamic terminator is not a bounded zero tag")) {
        free(source);
        return 0;
    }
    uint8_t *textrel_image = (uint8_t *)malloc(source_size);
    if (!fixture_expect(textrel_image != NULL, "could not allocate the text-relocation fixture")) {
        free(source);
        return 0;
    }
    memcpy(textrel_image, source, source_size);
    fixture_write_u64_le(textrel_image + flags_value_offset, UINT64_C(0x4));
    rejected_handle = 0U;
    status = adapter.context.load_image(
        adapter.context.userdata,
        textrel_image,
        source_size,
        URP_LOAD_IMAGE_IMMUTABLE,
        &rejected_handle);
    free(textrel_image);
    if (!fixture_expect(
            status == URP_STATUS_UNSUPPORTED,
            "a text-relocation dynamic flag was accepted")) {
        free(source);
        return 0;
    }

    uint8_t *dependency_image = (uint8_t *)malloc(source_size);
    if (!fixture_expect(
            dependency_image != NULL,
            "could not allocate the dynamic dependency fixture")) {
        free(source);
        return 0;
    }
    memcpy(dependency_image, source, source_size);
    fixture_write_u64_le(dependency_image + dynamic_terminator_offset, FIXTURE_DT_NEEDED);
    rejected_handle = 0U;
    status = adapter.context.load_image(
        adapter.context.userdata,
        dependency_image,
        source_size,
        URP_LOAD_IMAGE_IMMUTABLE,
        &rejected_handle);
    free(dependency_image);
    if (!fixture_expect(
            status == URP_STATUS_UNSUPPORTED && rejected_handle == 0U,
            "a DT_NEEDED dynamic entry was accepted or returned a handle")) {
        free(source);
        return 0;
    }

    static const fixture_dynamic_rejection unsupported_dynamic_tags[] = {
        {FIXTURE_DT_INIT, "a DT_INIT lifecycle entry was accepted or returned a handle"},
        {FIXTURE_DT_FINI, "a DT_FINI lifecycle entry was accepted or returned a handle"},
        {FIXTURE_DT_RPATH, "a DT_RPATH path-search entry was accepted or returned a handle"},
        {FIXTURE_DT_RUNPATH, "a DT_RUNPATH path-search entry was accepted or returned a handle"},
        {FIXTURE_DT_INIT_ARRAY, "a DT_INIT_ARRAY lifecycle entry was accepted or returned a handle"},
        {FIXTURE_DT_FINI_ARRAY, "a DT_FINI_ARRAY lifecycle entry was accepted or returned a handle"},
        {FIXTURE_DT_INIT_ARRAYSZ, "a DT_INIT_ARRAYSZ lifecycle entry was accepted or returned a handle"},
        {FIXTURE_DT_FINI_ARRAYSZ, "a DT_FINI_ARRAYSZ lifecycle entry was accepted or returned a handle"},
        {FIXTURE_DT_PREINIT_ARRAY, "a DT_PREINIT_ARRAY lifecycle entry was accepted or returned a handle"},
        {FIXTURE_DT_PREINIT_ARRAYSZ, "a DT_PREINIT_ARRAYSZ lifecycle entry was accepted or returned a handle"},
    };
    for (size_t index = 0;
         index < sizeof(unsupported_dynamic_tags) / sizeof(unsupported_dynamic_tags[0]);
         ++index) {
        uint8_t *unsupported_dynamic_image = (uint8_t *)malloc(source_size);
        if (!fixture_expect(
                unsupported_dynamic_image != NULL,
                "could not allocate an unsupported dynamic-tag fixture")) {
            free(source);
            return 0;
        }
        memcpy(unsupported_dynamic_image, source, source_size);
        fixture_write_u64_le(
            unsupported_dynamic_image + dynamic_terminator_offset,
            unsupported_dynamic_tags[index].tag);
        size_t dynamic_terminator_tail_offset =
            dynamic_terminator_offset + sizeof(uint64_t);
        size_t dynamic_terminator_tail_size = source_size - dynamic_terminator_tail_offset;
        int preserved = (dynamic_terminator_offset == 0U
                || memcmp(
                    unsupported_dynamic_image,
                    source,
                    dynamic_terminator_offset) == 0)
            && (dynamic_terminator_tail_size == 0U
                || memcmp(
                    unsupported_dynamic_image + dynamic_terminator_tail_offset,
                    source + dynamic_terminator_tail_offset,
                    dynamic_terminator_tail_size) == 0);
        if (!fixture_expect(
                preserved
                    && fixture_read_u64_le(
                        unsupported_dynamic_image + dynamic_terminator_offset)
                        == unsupported_dynamic_tags[index].tag,
                "unsupported dynamic-tag mutation changed bytes outside the terminator tag")) {
            free(unsupported_dynamic_image);
            free(source);
            return 0;
        }
        rejected_handle = 0U;
        status = adapter.context.load_image(
            adapter.context.userdata,
            unsupported_dynamic_image,
            source_size,
            URP_LOAD_IMAGE_IMMUTABLE,
            &rejected_handle);
        free(unsupported_dynamic_image);
        if (!fixture_expect(
                status == URP_STATUS_UNSUPPORTED && rejected_handle == 0U,
                unsupported_dynamic_tags[index].message)) {
            free(source);
            return 0;
        }
    }

    status = adapter.context.load_image(
        adapter.context.userdata,
        fixture_frame,
        sizeof(fixture_frame),
        0U,
        &rejected_handle);
    if (!fixture_expect(status == URP_STATUS_INVALID_ARGUMENT, "mutable adapter load was accepted")
        || !fixture_expect(rejected_handle == 0U, "failed adapter load returned a handle")) {
        free(source);
        return 0;
    }

    status = adapter.context.load_image(
        adapter.context.userdata,
        fixture_frame,
        sizeof(fixture_frame),
        URP_LOAD_IMAGE_IMMUTABLE,
        &rejected_handle);
    if (!fixture_expect(status == URP_STATUS_LOAD_FAILED, "non-ELF adapter input was accepted")) {
        free(source);
        return 0;
    }

    uint64_t program_header_offset = fixture_read_u64_le(source + 32U);
    size_t program_header_offset_as_size;
    if (!fixture_expect(
            fixture_range_in_file(
                source_size,
                program_header_offset,
                FIXTURE_ELF_PROGRAM_HEADER_SIZE,
                &program_header_offset_as_size,
                NULL),
            "entry fixture program headers are outside the source")) {
        free(source);
        return 0;
    }

    const uint8_t *load_header;
    if (!fixture_expect(
            fixture_find_program_header(source, source_size, FIXTURE_PT_LOAD, &load_header),
            "entry fixture has no PT_LOAD header for the PT_TLS boundary")) {
        free(source);
        return 0;
    }
    uint64_t load_file_offset = fixture_read_u64_le(load_header + 8U);
    uint64_t load_virtual_address = fixture_read_u64_le(load_header + 16U);
    uint64_t load_file_size = fixture_read_u64_le(load_header + 32U);
    uint64_t load_memory_size = fixture_read_u64_le(load_header + 40U);
    if (!fixture_expect(
            load_file_size > 0U && load_memory_size >= load_file_size,
            "entry fixture PT_LOAD has an empty or invalid range")) {
        free(source);
        return 0;
    }
    if (!fixture_expect(
            fixture_range_in_file(source_size, load_file_offset, load_file_size, NULL, NULL),
            "entry fixture PT_LOAD file-backed range is outside the source")) {
        free(source);
        return 0;
    }

    const uint8_t *tls_header;
    if (!fixture_expect(
            fixture_find_program_header(
                source,
                source_size,
                FIXTURE_PT_GNU_EH_FRAME,
                &tls_header),
            "entry fixture has no bounded metadata segment for the PT_TLS boundary")) {
        free(source);
        return 0;
    }
    size_t tls_header_offset = (size_t)(tls_header - source);
    uint64_t tls_file_offset = fixture_read_u64_le(tls_header + 8U);
    uint64_t tls_virtual_address = fixture_read_u64_le(tls_header + 16U);
    uint64_t tls_file_size = fixture_read_u64_le(tls_header + 32U);
    uint64_t tls_memory_size = fixture_read_u64_le(tls_header + 40U);
    if (!fixture_expect(
            tls_file_size > 0U && tls_memory_size >= tls_file_size,
            "entry fixture PT_TLS source range is empty or invalid")) {
        free(source);
        return 0;
    }
    if (!fixture_expect(
            fixture_range_in_file(source_size, tls_file_offset, tls_file_size, NULL, NULL),
            "entry fixture PT_TLS file-backed range is outside the source")) {
        free(source);
        return 0;
    }
    if (!fixture_expect(
            fixture_range_within(
                load_file_offset,
                load_file_size,
                tls_file_offset,
                tls_file_size)
                && fixture_range_within(
                    load_virtual_address,
                    load_memory_size,
                    tls_virtual_address,
                    tls_memory_size),
            "entry fixture PT_TLS source range is not inside a PT_LOAD range")) {
        free(source);
        return 0;
    }

    uint8_t *tls_image = (uint8_t *)malloc(source_size);
    if (!fixture_expect(tls_image != NULL, "could not allocate the PT_TLS fixture")) {
        free(source);
        return 0;
    }
    memcpy(tls_image, source, source_size);
    fixture_write_u32_le(tls_image + tls_header_offset, FIXTURE_PT_TLS);
    rejected_handle = UINT64_C(0xfeedface);
    status = adapter.context.load_image(
        adapter.context.userdata,
        tls_image,
        source_size,
        URP_LOAD_IMAGE_IMMUTABLE,
        &rejected_handle);
    free(tls_image);
    if (!fixture_expect(
            status == URP_STATUS_UNSUPPORTED && rejected_handle == 0U,
            "a structurally bounded PT_TLS image was accepted or returned a handle")) {
        free(source);
        return 0;
    }

    uint8_t *malformed_tls_image = (uint8_t *)malloc(source_size);
    if (!fixture_expect(
            malformed_tls_image != NULL,
            "could not allocate the malformed PT_TLS fixture")) {
        free(source);
        return 0;
    }
    memcpy(malformed_tls_image, source, source_size);
    fixture_write_u32_le(malformed_tls_image + tls_header_offset, FIXTURE_PT_TLS);
    fixture_write_u64_le(malformed_tls_image + tls_header_offset + 40U, tls_file_size - 1U);
    rejected_handle = UINT64_C(0xfeedface);
    status = adapter.context.load_image(
        adapter.context.userdata,
        malformed_tls_image,
        source_size,
        URP_LOAD_IMAGE_IMMUTABLE,
        &rejected_handle);
    free(malformed_tls_image);
    if (!fixture_expect(
            status == URP_STATUS_LOAD_FAILED && rejected_handle == 0U,
            "a PT_TLS file-size/memory-size violation was not rejected")) {
        free(source);
        return 0;
    }

    uint8_t *gnu_property_image = (uint8_t *)malloc(source_size);
    if (!fixture_expect(
            gnu_property_image != NULL,
            "could not allocate the PT_GNU_PROPERTY fixture")) {
        free(source);
        return 0;
    }
    memcpy(gnu_property_image, source, source_size);
    fixture_write_u32_le(
        gnu_property_image + program_header_offset_as_size,
        FIXTURE_PT_GNU_PROPERTY);
    rejected_handle = 0U;
    status = adapter.context.load_image(
        adapter.context.userdata,
        gnu_property_image,
        source_size,
        URP_LOAD_IMAGE_IMMUTABLE,
        &rejected_handle);
    free(gnu_property_image);
    if (!fixture_expect(
            status == URP_STATUS_UNSUPPORTED && rejected_handle == 0U,
            "a PT_GNU_PROPERTY program header was accepted or returned a handle")) {
        free(source);
        return 0;
    }

    uint8_t *interpreter_image = (uint8_t *)malloc(source_size);
    if (!fixture_expect(interpreter_image != NULL, "could not allocate negative adapter fixture")) {
        free(source);
        return 0;
    }
    memcpy(interpreter_image, source, source_size);
    fixture_write_u32_le(interpreter_image + program_header_offset_as_size, 3U);
    rejected_handle = 0U;
    status = adapter.context.load_image(
        adapter.context.userdata,
        interpreter_image,
        source_size,
        URP_LOAD_IMAGE_IMMUTABLE,
        &rejected_handle);
    free(interpreter_image);
    free(source);
    return fixture_expect(status == URP_STATUS_UNSUPPORTED, "PT_INTERP adapter input was accepted");
}

int main(int argc, char **argv)
{
    if (!fixture_expect(argc == 2, "the entry fixture path is required")) {
        return 2;
    }

    if (!fixture_expect(sizeof(urp_host_context_v1) == 56U, "context size changed")
        || !fixture_expect(sizeof(urp_launch_args_v1) == 32U, "launch args size changed")
        || !fixture_expect(URP_HOST_CONTEXT_MIN_SIZE == 56U, "context minimum size changed")
        || !fixture_expect(URP_LAUNCH_ARGS_MIN_SIZE == 32U, "launch args minimum size changed")) {
        return 1;
    }

    fixture_state state = {0};
    const char *fake_argv[] = {"fixture", NULL};
    const char *fake_envp[] = {NULL};
    urp_launch_args_v1 args = {
        .abi_version = URP_HOST_ABI_VERSION,
        .struct_size = sizeof(urp_launch_args_v1),
        .argc = 1U,
        .argv = fake_argv,
        .envp = fake_envp,
    };
    urp_host_context_v1 host = {
        .abi_version = URP_HOST_ABI_VERSION,
        .struct_size = sizeof(urp_host_context_v1),
        .capabilities = URP_HOST_CAP_LOAD_IMAGE
            | URP_HOST_CAP_LOOKUP_SYMBOL
            | URP_HOST_CAP_RELEASE_IMAGE
            | URP_HOST_CAP_EMIT_DIAGNOSTIC,
        .userdata = &state,
        .load_image = fixture_load_image,
        .lookup_symbol = fixture_lookup_symbol,
        .release_image = fixture_release_image,
        .emit_diagnostic = fixture_emit_diagnostic,
    };

    urp_status status = urp_runtime_execute_frame(
        &host,
        fixture_frame,
        sizeof(fixture_frame),
        &args);
    if (!fixture_expect(status == 17, "entry status was not preserved")
        || !fixture_expect(state.loaded && state.immutable, "immutable image was not loaded")
        || !fixture_expect(state.looked_up && state.entry_called, "entry was not dispatched")
        || !fixture_expect(state.released, "image lifetime was not released")
        || !fixture_expect(state.diagnostics == 0, "unexpected diagnostic on entry result")) {
        return 1;
    }

    static const uint8_t v2_source[] = "host-context-entry-fixture\n";
    uint8_t *v2_frame = NULL;
    size_t v2_frame_size = 0U;
    if (!fixture_expect(
            fixture_make_v2_frame(
                v2_source,
                sizeof(v2_source) - 1U,
                "fixture",
                "custom_entry",
                &v2_frame,
                &v2_frame_size),
            "could not construct the v2 HostContext frame")) {
        return 1;
    }

    fixture_state v2_state = {0};
    v2_state.expected_entry_name = "custom_entry";
    urp_host_context_v1 v2_host = host;
    v2_host.userdata = &v2_state;
    status = urp_runtime_execute_frame(&v2_host, v2_frame, v2_frame_size, &args);
    if (!fixture_expect(status == 17, "v2 entry status was not preserved")
        || !fixture_expect(v2_state.loaded && v2_state.immutable, "v2 image was not loaded")
        || !fixture_expect(v2_state.looked_up && v2_state.entry_called, "v2 entry was not dispatched")
        || !fixture_expect(v2_state.released, "v2 image lifetime was not released")) {
        free(v2_frame);
        return 1;
    }

    uint8_t *invalid_capabilities = (uint8_t *)malloc(v2_frame_size);
    if (!fixture_expect(invalid_capabilities != NULL, "could not allocate invalid v2 frame")) {
        free(v2_frame);
        return 1;
    }
    memcpy(invalid_capabilities, v2_frame, v2_frame_size);
    fixture_write_u64_le(
        invalid_capabilities + URP_RUNTIME_FRAME_V2_REQUIRED_CAPABILITIES_OFFSET,
        UINT64_C(1) << 63U);
    fixture_state invalid_v2_state = {0};
    invalid_v2_state.expected_entry_name = "custom_entry";
    urp_host_context_v1 invalid_v2_host = v2_host;
    invalid_v2_host.userdata = &invalid_v2_state;
    status = urp_runtime_execute_frame(
        &invalid_v2_host,
        invalid_capabilities,
        v2_frame_size,
        &args);

    uint8_t *invalid_entry_name = (uint8_t *)malloc(v2_frame_size);
    if (!fixture_expect(invalid_entry_name != NULL, "could not allocate invalid v2 entry frame")) {
        free(invalid_capabilities);
        free(v2_frame);
        return 1;
    }
    memcpy(invalid_entry_name, v2_frame, v2_frame_size);
    invalid_entry_name[
        URP_RUNTIME_FRAME_V2_HEADER_SIZE + strlen("fixture")] = UINT8_C(0xFF);
    fixture_state invalid_entry_state = {0};
    invalid_entry_state.expected_entry_name = "custom_entry";
    urp_host_context_v1 invalid_entry_host = v2_host;
    invalid_entry_host.userdata = &invalid_entry_state;
    urp_status invalid_entry_status = urp_runtime_execute_frame(
        &invalid_entry_host,
        invalid_entry_name,
        v2_frame_size,
        &args);
    free(invalid_capabilities);
    free(invalid_entry_name);
    free(v2_frame);
    if (!fixture_expect(
            status == URP_STATUS_UNSUPPORTED,
            "unsupported v2 capability was accepted")
        || !fixture_expect(
            invalid_v2_state.loaded == 0,
            "invalid v2 capability reached the host loader")
        || !fixture_expect(
            invalid_entry_status == URP_STATUS_FRAME_INVALID,
            "invalid v2 UTF-8 entry name was accepted")
        || !fixture_expect(
            invalid_entry_state.loaded == 0,
            "invalid v2 entry name reached the host loader")) {
        return 1;
    }

    urp_host_context_v1 invalid_host = host;
    invalid_host.abi_version = 2U;
    status = urp_runtime_execute_frame(&invalid_host, fixture_frame, sizeof(fixture_frame), &args);
    if (!fixture_expect(status == URP_STATUS_HOST_INVALID, "unknown host ABI was accepted")) {
        return 1;
    }

    uint8_t tampered_frame[sizeof(fixture_frame)];
    memcpy(tampered_frame, fixture_frame, sizeof(tampered_frame));
    tampered_frame[sizeof(tampered_frame) - 1U] ^= 1U;
    status = urp_runtime_execute_frame(&host, tampered_frame, sizeof(tampered_frame), &args);
    if (!fixture_expect(status == URP_STATUS_INTEGRITY_FAILURE, "tampered frame was accepted")) {
        return 1;
    }

    uint8_t wrong_header_size[sizeof(fixture_frame)];
    memcpy(wrong_header_size, fixture_frame, sizeof(wrong_header_size));
    fixture_write_u16_le(wrong_header_size + 10U, 0U);
    status = urp_runtime_execute_frame(&host, wrong_header_size, sizeof(wrong_header_size), &args);
    if (!fixture_expect(status == URP_STATUS_FRAME_INVALID, "invalid frame header size was accepted")) {
        return 1;
    }

    urp_launch_args_v1 short_args = args;
    short_args.struct_size = URP_LAUNCH_ARGS_MIN_SIZE - 1U;
    status = urp_runtime_execute_frame(&host, fixture_frame, sizeof(fixture_frame), &short_args);
    if (!fixture_expect(status == URP_STATUS_INVALID_ARGUMENT, "truncated launch args were accepted")) {
        return 1;
    }

    if (!fixture_run_real_adapter(argv[1])) {
        return 1;
    }

    puts("HostContext runtime self-test: PASS");
    return 0;
}
