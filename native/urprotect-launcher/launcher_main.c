#define _GNU_SOURCE

#include "sha256.h"
#include "miniz_tinfl.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define URP_TRAILER_SIZE 24U
#define URP_HEADER_SIZE 112U
#define URP_SHA256_SIZE 32U
#define URP_MAX_SOURCE_NAME 4096U
#define URP_MAX_SOURCE_SIZE (256ULL * 1024ULL * 1024ULL)
#define URP_MAX_ENCODED_SIZE (256ULL * 1024ULL * 1024ULL)
#define URP_MAX_WRAPPER_SIZE (512ULL * 1024ULL * 1024ULL)
#define URP_FORMAT_VERSION 1U
#define URP_DEFLATE_FLAG 1U
#define URP_MACHINE_AARCH64 183U
#define URP_TYPE_DYN 3U
#define URP_ELF_CLASS_64 2U
#define URP_ELF_DATA_LSB 1U
#define URP_ELF_VERSION_CURRENT 1U
#define URP_PT_LOAD 1U
#define URP_PT_INTERP 3U
#define URP_PF_X 1U
#define URP_EXIT_FILE_SYSTEM 3
#define URP_EXIT_VALIDATION 4
#define URP_EXIT_INTEGRITY 5
#define URP_MAX_ARGUMENTS 4096U
#define URP_LAUNCHER_ABI_MARKER "URPROTECT-AARCH64-LAUNCHER-V1"

static const uint8_t urp_header_magic[8] = {'U', 'R', 'P', 'C', 'K', '0', '1', 0};
static const uint8_t urp_trailer_magic[8] = {'U', 'R', 'T', 'R', 'A', 'I', 'L', '1'};
static const char urp_launcher_abi_marker[] = URP_LAUNCHER_ABI_MARKER;

typedef struct urp_frame_view {
    const uint8_t *source_name;
    size_t source_name_size;
    const uint8_t *encoded;
    size_t encoded_size;
    uint64_t source_size;
    const uint8_t *source_sha256;
    const uint8_t *encoded_sha256;
} urp_frame_view;

static size_t urp_string_length(const char *value)
{
    return strlen(value);
}

static int urp_write_all(int fd, const void *buffer, size_t size)
{
    const uint8_t *bytes = (const uint8_t *)buffer;
    size_t offset = 0;
    while (offset < size) {
        ssize_t written = write(fd, bytes + offset, size - offset);
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

static int urp_launcher_abi_is_valid(void)
{
    volatile const char *marker = urp_launcher_abi_marker;
    return marker[0] == 'U'
        && marker[sizeof(URP_LAUNCHER_ABI_MARKER) - 2U] == '1'
        && marker[sizeof(URP_LAUNCHER_ABI_MARKER) - 1U] == '\0';
}

static int urp_report(int status, const char *code, const char *message)
{
    (void)urp_write_all(STDERR_FILENO, code, urp_string_length(code));
    (void)urp_write_all(STDERR_FILENO, ": ", 2U);
    (void)urp_write_all(STDERR_FILENO, message, urp_string_length(message));
    (void)urp_write_all(STDERR_FILENO, "\n", 1U);
    return status;
}

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

static int urp_checked_mul_u64(uint64_t left, uint64_t right, uint64_t *result)
{
    if (left != 0U && right > UINT64_MAX / left) {
        return 0;
    }
    *result = left * right;
    return 1;
}

static int urp_u64_to_size(uint64_t value, size_t *result)
{
    if (value > (uint64_t)SIZE_MAX) {
        return 0;
    }
    *result = (size_t)value;
    return 1;
}

static int urp_range_in_file(
    size_t file_size,
    uint64_t offset,
    uint64_t length,
    size_t *offset_out,
    size_t *length_out)
{
    uint64_t end;
    if (!urp_checked_add_u64(offset, length, &end)
        || end > (uint64_t)file_size) {
        return 0;
    }
    if (offset_out != NULL && !urp_u64_to_size(offset, offset_out)) {
        return 0;
    }
    if (length_out != NULL && !urp_u64_to_size(length, length_out)) {
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

static int urp_is_continuation(uint8_t value)
{
    return (value & 0xC0U) == 0x80U;
}

static int urp_is_unicode_whitespace(uint32_t codepoint)
{
    return (codepoint <= 0x20U)
        || codepoint == 0x85U
        || codepoint == 0xA0U
        || codepoint == 0x1680U
        || (codepoint >= 0x2000U && codepoint <= 0x200AU)
        || codepoint == 0x2028U
        || codepoint == 0x2029U
        || codepoint == 0x202FU
        || codepoint == 0x205FU
        || codepoint == 0x3000U;
}

static int urp_validate_source_name(const uint8_t *bytes, size_t size)
{
    if (size == 0U || (size == 1U && bytes[0] == '.')
        || (size == 2U && bytes[0] == '.' && bytes[1] == '.')) {
        return 0;
    }

    size_t offset = 0;
    int has_non_whitespace = 0;
    while (offset < size) {
        uint8_t first = bytes[offset];
        uint32_t codepoint;
        size_t width;
        if (first < 0x80U) {
            codepoint = first;
            width = 1U;
        } else if (first >= 0xC2U && first <= 0xDFU) {
            if (offset + 2U > size || !urp_is_continuation(bytes[offset + 1U])) {
                return 0;
            }
            codepoint = ((uint32_t)(first & 0x1FU) << 6U)
                | (uint32_t)(bytes[offset + 1U] & 0x3FU);
            width = 2U;
        } else if (first >= 0xE0U && first <= 0xEFU) {
            if (offset + 3U > size
                || !urp_is_continuation(bytes[offset + 1U])
                || !urp_is_continuation(bytes[offset + 2U])) {
                return 0;
            }
            uint8_t second = bytes[offset + 1U];
            if ((first == 0xE0U && second < 0xA0U)
                || (first == 0xEDU && second >= 0xA0U)) {
                return 0;
            }
            codepoint = ((uint32_t)(first & 0x0FU) << 12U)
                | ((uint32_t)(second & 0x3FU) << 6U)
                | (uint32_t)(bytes[offset + 2U] & 0x3FU);
            width = 3U;
        } else if (first >= 0xF0U && first <= 0xF4U) {
            if (offset + 4U > size
                || !urp_is_continuation(bytes[offset + 1U])
                || !urp_is_continuation(bytes[offset + 2U])
                || !urp_is_continuation(bytes[offset + 3U])) {
                return 0;
            }
            uint8_t second = bytes[offset + 1U];
            if ((first == 0xF0U && second < 0x90U)
                || (first == 0xF4U && second >= 0x90U)) {
                return 0;
            }
            codepoint = ((uint32_t)(first & 0x07U) << 18U)
                | ((uint32_t)(second & 0x3FU) << 12U)
                | ((uint32_t)(bytes[offset + 2U] & 0x3FU) << 6U)
                | (uint32_t)(bytes[offset + 3U] & 0x3FU);
            width = 4U;
        } else {
            return 0;
        }

        for (size_t index = 0; index < width; ++index) {
            if (bytes[offset + index] == 0U
                || bytes[offset + index] == (uint8_t)'/'
                || bytes[offset + index] == (uint8_t)'\\') {
                return 0;
            }
        }
        if (!urp_is_unicode_whitespace(codepoint)) {
            has_non_whitespace = 1;
        }
        offset += width;
    }
    return has_non_whitespace;
}

static int urp_read_self(uint8_t **bytes_out, size_t *size_out)
{
    *bytes_out = NULL;
    *size_out = 0;
    int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return 0;
    }

    struct stat info;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size <= 0) {
        (void)close(fd);
        return 0;
    }
    uint64_t file_size = (uint64_t)info.st_size;
    size_t size;
    if (file_size > URP_MAX_WRAPPER_SIZE || !urp_u64_to_size(file_size, &size)) {
        (void)close(fd);
        return 0;
    }

    uint8_t *bytes = (uint8_t *)malloc(size);
    if (bytes == NULL) {
        (void)close(fd);
        return 0;
    }
    size_t offset = 0;
    while (offset < size) {
        if ((uint64_t)offset > (uint64_t)INT64_MAX) {
            free(bytes);
            (void)close(fd);
            return 0;
        }
        ssize_t read_count = pread(fd, bytes + offset, size - offset, (off_t)offset);
        if (read_count < 0 && errno == EINTR) {
            continue;
        }
        if (read_count <= 0) {
            free(bytes);
            (void)close(fd);
            return 0;
        }
        offset += (size_t)read_count;
    }
    (void)close(fd);
    *bytes_out = bytes;
    *size_out = size;
    return 1;
}

static int urp_parse_frame(
    const uint8_t *wrapper,
    size_t wrapper_size,
    urp_frame_view *frame)
{
    if (wrapper_size < URP_TRAILER_SIZE) {
        return 0;
    }
    const uint8_t *trailer = wrapper + (wrapper_size - URP_TRAILER_SIZE);
    if (memcmp(trailer, urp_trailer_magic, sizeof(urp_trailer_magic)) != 0) {
        return 0;
    }

    uint64_t frame_offset = urp_read_u64_le(trailer + 8U);
    uint64_t frame_length = urp_read_u64_le(trailer + 16U);
    uint64_t frame_end;
    uint64_t wrapper_end;
    if (frame_length < URP_HEADER_SIZE
        || !urp_checked_add_u64(frame_offset, frame_length, &frame_end)
        || !urp_checked_add_u64(frame_end, URP_TRAILER_SIZE, &wrapper_end)
        || wrapper_end != (uint64_t)wrapper_size
        || frame_offset > (uint64_t)wrapper_size) {
        return 0;
    }

    size_t frame_offset_size;
    size_t frame_length_size;
    if (!urp_u64_to_size(frame_offset, &frame_offset_size)
        || !urp_u64_to_size(frame_length, &frame_length_size)) {
        return 0;
    }
    const uint8_t *header = wrapper + frame_offset_size;
    if (memcmp(header, urp_header_magic, sizeof(urp_header_magic)) != 0
        || urp_read_u16_le(header + 8U) != URP_FORMAT_VERSION
        || urp_read_u16_le(header + 10U) != URP_HEADER_SIZE
        || urp_read_u32_le(header + 12U) != URP_DEFLATE_FLAG
        || urp_read_u16_le(header + 16U) != URP_MACHINE_AARCH64
        || urp_read_u16_le(header + 18U) != URP_TYPE_DYN) {
        return 0;
    }

    uint32_t source_name_size_u32 = urp_read_u32_le(header + 20U);
    uint64_t source_size = urp_read_u64_le(header + 24U);
    uint64_t encoded_size_u64 = urp_read_u64_le(header + 32U);
    uint64_t encoded_offset = urp_read_u64_le(header + 40U);
    if (source_name_size_u32 > URP_MAX_SOURCE_NAME
        || source_size > URP_MAX_SOURCE_SIZE
        || encoded_size_u64 > URP_MAX_ENCODED_SIZE
        || (uint64_t)source_name_size_u32 > frame_length - URP_HEADER_SIZE) {
        return 0;
    }

    size_t source_name_size;
    size_t encoded_size;
    if (!urp_u64_to_size((uint64_t)source_name_size_u32, &source_name_size)
        || !urp_u64_to_size(encoded_size_u64, &encoded_size)
        || !urp_validate_source_name(header + URP_HEADER_SIZE, source_name_size)) {
        return 0;
    }

    uint64_t expected_encoded_offset;
    uint64_t name_offset;
    if (!urp_checked_add_u64(frame_offset, URP_HEADER_SIZE, &name_offset)
        || !urp_checked_add_u64(name_offset, (uint64_t)source_name_size, &expected_encoded_offset)
        || encoded_offset != expected_encoded_offset
        || !urp_checked_add_u64(encoded_offset, encoded_size_u64, &frame_end)
        || frame_end != (uint64_t)frame_offset + (uint64_t)frame_length
        || frame_length_size != URP_HEADER_SIZE + source_name_size + encoded_size) {
        return 0;
    }

    size_t encoded_offset_size;
    if (!urp_u64_to_size(encoded_offset, &encoded_offset_size)
        || encoded_offset_size > wrapper_size
        || encoded_size > wrapper_size - encoded_offset_size) {
        return 0;
    }

    frame->source_name = header + URP_HEADER_SIZE;
    frame->source_name_size = source_name_size;
    frame->encoded = wrapper + encoded_offset_size;
    frame->encoded_size = encoded_size;
    frame->source_size = source_size;
    frame->source_sha256 = header + 48U;
    frame->encoded_sha256 = header + 80U;
    return 1;
}

static int urp_decode_frame(
    const urp_frame_view *frame,
    uint8_t **source_out,
    size_t *source_size_out)
{
    size_t source_size;
    if (!urp_u64_to_size(frame->source_size, &source_size)
        || source_size == 0U) {
        return 0;
    }

    uint8_t encoded_digest[URP_SHA256_SIZE];
    urp_sha256_context encoded_context;
    urp_sha256_init(&encoded_context);
    urp_sha256_update(&encoded_context, frame->encoded, frame->encoded_size);
    urp_sha256_final(&encoded_context, encoded_digest);
    if (!urp_constant_time_equal(encoded_digest, frame->encoded_sha256, URP_SHA256_SIZE)) {
        return -1;
    }

    uint8_t *source = (uint8_t *)malloc(source_size);
    if (source == NULL) {
        return 0;
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
        return 0;
    }

    uint8_t source_digest[URP_SHA256_SIZE];
    urp_sha256_context source_context;
    urp_sha256_init(&source_context);
    urp_sha256_update(&source_context, source, source_size);
    urp_sha256_final(&source_context, source_digest);
    if (!urp_constant_time_equal(source_digest, frame->source_sha256, URP_SHA256_SIZE)) {
        free(source);
        return -1;
    }

    *source_out = source;
    *source_size_out = source_size;
    return 1;
}

static int urp_validate_interpreter(const uint8_t *bytes, size_t size)
{
    const char *linux_suffix = "ld-linux-aarch64.so.1";
    const char *musl_suffix = "ld-musl-aarch64.so.1";
    size_t path_size = 0;
    while (path_size < size && bytes[path_size] != 0U) {
        ++path_size;
    }
    if (path_size == 0U || path_size == size || bytes[0] != '/') {
        return 0;
    }
    size_t linux_length = strlen(linux_suffix);
    size_t musl_length = strlen(musl_suffix);
    int linux_match = path_size >= linux_length
        && memcmp(bytes + path_size - linux_length, linux_suffix, linux_length) == 0;
    int musl_match = path_size >= musl_length
        && memcmp(bytes + path_size - musl_length, musl_suffix, musl_length) == 0;
    return linux_match || musl_match;
}

static int urp_validate_recovered_elf(const uint8_t *source, size_t source_size)
{
    if (source_size < 64U
        || source[0] != 0x7FU
        || source[1] != 'E'
        || source[2] != 'L'
        || source[3] != 'F'
        || source[4] != 2U
        || source[5] != 1U
        || source[6] != URP_ELF_VERSION_CURRENT
        || urp_read_u16_le(source + 16U) != URP_TYPE_DYN
        || urp_read_u16_le(source + 18U) != URP_MACHINE_AARCH64
        || urp_read_u32_le(source + 20U) != URP_ELF_VERSION_CURRENT
        || urp_read_u16_le(source + 52U) != 64U
        || urp_read_u16_le(source + 54U) != 56U) {
        return 0;
    }

    uint64_t program_header_offset = urp_read_u64_le(source + 32U);
    uint16_t program_header_count = urp_read_u16_le(source + 56U);
    uint64_t program_header_size;
    uint64_t program_header_end;
    if (program_header_count == 0U
        || !urp_checked_mul_u64(56U, program_header_count, &program_header_size)
        || !urp_checked_add_u64(program_header_offset, program_header_size, &program_header_end)
        || program_header_end > (uint64_t)source_size) {
        return 0;
    }

    uint64_t entry = urp_read_u64_le(source + 24U);
    int has_load = 0;
    int has_executable_entry = 0;
    int has_interpreter = 0;
    for (uint16_t index = 0; index < program_header_count; ++index) {
        uint64_t current_offset;
        if (!urp_checked_add_u64(program_header_offset, (uint64_t)index * 56U, &current_offset)) {
            return 0;
        }
        size_t current_offset_size;
        if (!urp_u64_to_size(current_offset, &current_offset_size)) {
            return 0;
        }
        const uint8_t *program = source + current_offset_size;
        uint32_t type = urp_read_u32_le(program);
        uint32_t flags = urp_read_u32_le(program + 4U);
        uint64_t file_offset = urp_read_u64_le(program + 8U);
        uint64_t virtual_address = urp_read_u64_le(program + 16U);
        uint64_t file_size = urp_read_u64_le(program + 32U);
        uint64_t memory_size = urp_read_u64_le(program + 40U);
        uint64_t segment_end;
        if (type == URP_PT_LOAD) {
            has_load = 1;
            if (file_size > memory_size
                || !urp_checked_add_u64(file_offset, file_size, &segment_end)
                || segment_end > (uint64_t)source_size
                || !urp_checked_add_u64(virtual_address, memory_size, &segment_end)) {
                return 0;
            }
            if ((flags & URP_PF_X) != 0U
                && entry >= virtual_address
                && entry - virtual_address < file_size) {
                has_executable_entry = 1;
            }
        } else if (type == URP_PT_INTERP) {
            if (has_interpreter
                || !urp_range_in_file(source_size, file_offset, file_size, NULL, NULL)) {
                return 0;
            }
            size_t interpreter_offset;
            size_t interpreter_size;
            if (!urp_range_in_file(
                    source_size,
                    file_offset,
                    file_size,
                    &interpreter_offset,
                    &interpreter_size)
                || !urp_validate_interpreter(source + interpreter_offset, interpreter_size)) {
                return 0;
            }
            has_interpreter = 1;
        }
    }
    return has_load && has_executable_entry && has_interpreter;
}

static void urp_cleanup_payload(const char *directory, const char *payload_path)
{
    if (payload_path != NULL) {
        (void)unlink(payload_path);
    }
    if (directory != NULL) {
        (void)rmdir(directory);
    }
}

static void urp_cleanup_payload_at(int directory_fd, const char *directory, const char *source_name)
{
    if (directory_fd >= 0) {
        (void)unlinkat(directory_fd, source_name, 0);
        (void)close(directory_fd);
    }
    if (directory != NULL) {
        (void)rmdir(directory);
    }
}

static int urp_write_payload_and_exec(
    const urp_frame_view *frame,
    const uint8_t *source,
    size_t source_size,
    int argc,
    char *const argv[],
    char *const envp[])
{
    if (argc <= 0 || (uint32_t)argc > URP_MAX_ARGUMENTS) {
        return urp_report(URP_EXIT_VALIDATION, "InvalidArgument", "the command line is outside the supported bounds");
    }

    char source_name[URP_MAX_SOURCE_NAME + 1U];
    memcpy(source_name, frame->source_name, frame->source_name_size);
    source_name[frame->source_name_size] = '\0';

    char directory[] = "/tmp/urprotect-payload-XXXXXX";
    if (mkdtemp(directory) == NULL) {
        return urp_report(URP_EXIT_FILE_SYSTEM, "OutputIoFailure", "could not create a private payload directory");
    }
    if (chmod(directory, 0700) != 0) {
        urp_cleanup_payload(directory, NULL);
        return urp_report(URP_EXIT_FILE_SYSTEM, "OutputIoFailure", "could not create a private payload directory");
    }

    size_t directory_size = strlen(directory);
    if (directory_size + 1U + frame->source_name_size + 1U > PATH_MAX) {
        urp_cleanup_payload(directory, NULL);
        return urp_report(URP_EXIT_FILE_SYSTEM, "OutputIoFailure", "the recovered payload path is too long");
    }
    char payload_path[PATH_MAX];
    memcpy(payload_path, directory, directory_size);
    payload_path[directory_size] = '/';
    memcpy(payload_path + directory_size + 1U, source_name, frame->source_name_size + 1U);

    int directory_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0) {
        urp_cleanup_payload(directory, NULL);
        return urp_report(URP_EXIT_FILE_SYSTEM, "OutputIoFailure", "could not open the private payload directory");
    }
    int payload_fd = openat(
        directory_fd,
        source_name,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
        0700);
    if (payload_fd < 0) {
        urp_cleanup_payload_at(directory_fd, directory, source_name);
        return urp_report(URP_EXIT_FILE_SYSTEM, "OutputIoFailure", "could not create the private payload file");
    }

    size_t offset = 0;
    int write_ok = 1;
    while (offset < source_size) {
        ssize_t written = write(payload_fd, source + offset, source_size - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            write_ok = 0;
            break;
        }
        offset += (size_t)written;
    }
    if (write_ok && (fchmod(payload_fd, 0700) != 0 || fsync(payload_fd) != 0)) {
        write_ok = 0;
    }
    if (close(payload_fd) != 0) {
        write_ok = 0;
    }
    if (fsync(directory_fd) != 0) {
        write_ok = 0;
    }
    if (!write_ok) {
        urp_cleanup_payload_at(directory_fd, directory, source_name);
        return urp_report(URP_EXIT_FILE_SYSTEM, "OutputIoFailure", "could not persist the recovered payload");
    }

    size_t argument_count = (size_t)argc;
    if (argument_count > (SIZE_MAX / sizeof(char *)) - 1U) {
        urp_cleanup_payload_at(directory_fd, directory, source_name);
        return urp_report(URP_EXIT_VALIDATION, "InvalidArgument", "the command line size overflows the launcher bounds");
    }
    char **exec_argv = (char **)malloc((argument_count + 1U) * sizeof(char *));
    if (exec_argv == NULL) {
        urp_cleanup_payload_at(directory_fd, directory, source_name);
        return urp_report(URP_EXIT_FILE_SYSTEM, "OutputIoFailure", "could not allocate the recovered argument vector");
    }
    exec_argv[0] = source_name;
    for (size_t index = 1U; index < argument_count; ++index) {
        exec_argv[index] = argv[index];
    }
    exec_argv[argument_count] = NULL;

    execve(payload_path, exec_argv, envp);
    free(exec_argv);
    urp_cleanup_payload_at(directory_fd, directory, source_name);
    return urp_report(URP_EXIT_FILE_SYSTEM, "OutputIoFailure", "execve failed for the recovered payload");
}

int main(int argc, char **argv, char **envp)
{
    if (!urp_launcher_abi_is_valid()) {
        return urp_report(URP_EXIT_VALIDATION, "LauncherAbiMismatch", "the native launcher ABI marker is invalid");
    }

    uint8_t *wrapper = NULL;
    size_t wrapper_size = 0;
    if (!urp_read_self(&wrapper, &wrapper_size)) {
        return urp_report(URP_EXIT_FILE_SYSTEM, "InputIoFailure", "could not inspect /proc/self/exe");
    }

    urp_frame_view frame;
    if (!urp_parse_frame(wrapper, wrapper_size, &frame)) {
        free(wrapper);
        return urp_report(URP_EXIT_VALIDATION, "WrapperMalformed", "the v1 payload frame or trailer is malformed");
    }

    uint8_t *source = NULL;
    size_t source_size = 0;
    int decode_result = urp_decode_frame(&frame, &source, &source_size);
    if (decode_result < 0) {
        free(wrapper);
        return urp_report(URP_EXIT_INTEGRITY, "PayloadIntegrityMismatch", "the payload digest does not match");
    }
    if (decode_result == 0 || source == NULL) {
        free(wrapper);
        return urp_report(URP_EXIT_VALIDATION, "PayloadMalformed", "the raw-deflate payload is invalid or exceeds its bounds");
    }
    if (!urp_validate_recovered_elf(source, source_size)) {
        free(source);
        free(wrapper);
        return urp_report(URP_EXIT_VALIDATION, "UnsupportedPackInput", "the recovered payload is not a supported AArch64 ET_DYN executable");
    }

    int result = urp_write_payload_and_exec(&frame, source, source_size, argc, argv, envp);
    free(source);
    free(wrapper);
    return result;
}
