#define _GNU_SOURCE

#include "sha256.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

#define MAX_IMAGE_BYTES (128U * 1024U * 1024U)
#define MAX_CAPTURE_BYTES (1024U * 1024U)
#define MAX_ARGUMENTS 256U
#define MAX_ARGUMENT_BYTES (128U * 1024U)
#define MEMFD_FLAGS (MFD_CLOEXEC | MFD_ALLOW_SEALING)
#define REQUIRED_SEALS (F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL)
#define AT_EMPTY_PATH_VALUE 0x1000

typedef struct child_exec_failure {
    int stage;
    int error_number;
} child_exec_failure;

typedef struct handoff_state {
    bool memfd_created;
    bool fchmod_passed;
    bool fsync_passed;
    bool seals_supported;
    bool seals_applied;
    bool execveat_invoked;
    bool execveat_passed;
    bool stdout_truncated;
    bool stderr_truncated;
    int target_status;
    int target_signal;
    uint64_t stdout_bytes;
    uint64_t stderr_bytes;
    uint64_t duration_ns;
    uint64_t max_rss_bytes;
    const char *diagnostic;
    const char *rehydration_record_sha256;
} handoff_state;

static uint64_t monotonic_nanoseconds(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
        return 0U;
    }
    return ((uint64_t)value.tv_sec * UINT64_C(1000000000)) + (uint64_t)value.tv_nsec;
}

static bool parse_limit(const char *text, size_t *limit_out)
{
    if (text == NULL || text[0] == '\0') {
        return false;
    }
    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0'
        || parsed == 0ULL || parsed > (unsigned long long)MAX_CAPTURE_BYTES) {
        return false;
    }
    *limit_out = (size_t)parsed;
    return true;
}

static bool is_hex_digest(const char *value)
{
    if (value == NULL || strlen(value) != 64U) {
        return false;
    }
    for (size_t index = 0U; index < 64U; ++index) {
        const char character = value[index];
        if (!((character >= '0' && character <= '9')
            || (character >= 'a' && character <= 'f')
            || (character >= 'A' && character <= 'F'))) {
            return false;
        }
    }
    return true;
}

static void digest_hex(const uint8_t digest[32], char output[65])
{
    static const char hex[] = "0123456789abcdef";
    for (size_t index = 0U; index < 32U; ++index) {
        output[index * 2U] = hex[digest[index] >> 4U];
        output[(index * 2U) + 1U] = hex[digest[index] & 0x0fU];
    }
    output[64] = '\0';
}

static bool digest_matches(const char *expected, const char *actual)
{
    if (expected == NULL || actual == NULL || strlen(expected) != 64U || strlen(actual) != 64U) {
        return false;
    }
    for (size_t index = 0U; index < 64U; ++index) {
        char left = expected[index];
        char right = actual[index];
        if (left >= 'A' && left <= 'F') {
            left = (char)(left - 'A' + 'a');
        }
        if (right >= 'A' && right <= 'F') {
            right = (char)(right - 'A' + 'a');
        }
        if (left != right) {
            return false;
        }
    }
    return true;
}

static bool json_escape(const char *value, char *output, size_t capacity)
{
    static const char hex[] = "0123456789abcdef";
    size_t cursor = 0U;
    if (output == NULL || capacity == 0U) {
        return false;
    }
    if (value == NULL) {
        value = "";
    }
    for (const unsigned char *input = (const unsigned char *)value; *input != '\0'; ++input) {
        const unsigned char character = *input;
        if (character == '"' || character == '\\') {
            if (cursor > capacity - 2U) {
                return false;
            }
            output[cursor++] = '\\';
            output[cursor++] = (char)character;
        } else if (character == '\b' || character == '\f' || character == '\n'
            || character == '\r' || character == '\t') {
            if (cursor > capacity - 2U) {
                return false;
            }
            output[cursor++] = '\\';
            output[cursor++] = character == '\b' ? 'b'
                : character == '\f' ? 'f'
                : character == '\n' ? 'n'
                : character == '\r' ? 'r' : 't';
        } else if (character < 0x20U || character >= 0x80U) {
            if (cursor > capacity - 6U) {
                return false;
            }
            output[cursor++] = '\\';
            output[cursor++] = 'u';
            output[cursor++] = '0';
            output[cursor++] = '0';
            output[cursor++] = hex[character >> 4U];
            output[cursor++] = hex[character & 0x0fU];
        } else {
            if (cursor > capacity - 1U) {
                return false;
            }
            output[cursor++] = (char)character;
        }
    }
    if (cursor >= capacity) {
        return false;
    }
    output[cursor] = '\0';
    return true;
}

static bool write_all(int fd, const uint8_t *bytes, size_t length)
{
    size_t offset = 0U;
    while (offset < length) {
        ssize_t count = write(fd, bytes + offset, length - offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return false;
        }
        offset += (size_t)count;
    }
    return true;
}

static bool copy_image_to_memfd(int source_fd, int memfd, const uint8_t *bytes, size_t length)
{
    (void)source_fd;
    return write_all(memfd, bytes, length);
}

static int open_capture(const char *path)
{
    return open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, S_IRUSR | S_IWUSR);
}

static bool append_bounded(int fd, uint8_t *buffer, size_t count, size_t limit, uint64_t *total, bool *truncated)
{
    if ((uint64_t)count > UINT64_MAX - *total) {
        return false;
    }
    uint64_t previous = *total;
    *total += (uint64_t)count;
    if (previous >= (uint64_t)limit) {
        *truncated = true;
        return true;
    }
    size_t available = limit - (size_t)previous;
    size_t retained = count < available ? count : available;
    if (retained < count) {
        *truncated = true;
    }
    return retained == 0U || write_all(fd, buffer, retained);
}

static bool drain_stream(int *stream_fd, int output_fd, size_t limit, uint64_t *total, bool *truncated)
{
    uint8_t buffer[8192];
    for (;;) {
        ssize_t count = read(*stream_fd, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return true;
        }
        if (count < 0) {
            return false;
        }
        if (count == 0) {
            (void)close(*stream_fd);
            *stream_fd = -1;
            return true;
        }
        if (!append_bounded(output_fd, buffer, (size_t)count, limit, total, truncated)) {
            return false;
        }
    }
}

static bool capture_child_streams(
    pid_t child,
    int stdout_pipe[2],
    int stderr_pipe[2],
    int stdout_file,
    int stderr_file,
    size_t output_limit,
    handoff_state *state,
    int *exec_errno_out,
    struct rusage *usage_out)
{
    (void)close(stdout_pipe[1]);
    (void)close(stderr_pipe[1]);
    int stdout_fd = stdout_pipe[0];
    int stderr_fd = stderr_pipe[0];
    int child_status = 0;
    bool child_reaped = false;
    bool success = true;

    int stdout_flags = fcntl(stdout_fd, F_GETFL, 0);
    int stderr_flags = fcntl(stderr_fd, F_GETFL, 0);
    if (stdout_flags < 0 || stderr_flags < 0
        || fcntl(stdout_fd, F_SETFL, stdout_flags | O_NONBLOCK) < 0
        || fcntl(stderr_fd, F_SETFL, stderr_flags | O_NONBLOCK) < 0) {
        success = false;
    }

    while (success && (stdout_fd >= 0 || stderr_fd >= 0 || !child_reaped)) {
        struct pollfd descriptors[2];
        nfds_t descriptor_count = 0U;
        if (stdout_fd >= 0) {
            descriptors[descriptor_count].fd = stdout_fd;
            descriptors[descriptor_count].events = POLLIN | POLLHUP;
            descriptors[descriptor_count].revents = 0;
            descriptor_count++;
        }
        if (stderr_fd >= 0) {
            descriptors[descriptor_count].fd = stderr_fd;
            descriptors[descriptor_count].events = POLLIN | POLLHUP;
            descriptors[descriptor_count].revents = 0;
            descriptor_count++;
        }
        if (descriptor_count > 0U) {
            int poll_result;
            do {
                poll_result = poll(descriptors, descriptor_count, 100);
            } while (poll_result < 0 && errno == EINTR);
            if (poll_result < 0) {
                success = false;
                break;
            }
            nfds_t index = 0U;
            if (stdout_fd >= 0) {
                if ((descriptors[index].revents & (POLLIN | POLLHUP | POLLERR)) != 0
                    && !drain_stream(&stdout_fd, stdout_file, output_limit, &state->stdout_bytes, &state->stdout_truncated)) {
                    success = false;
                }
                index++;
            }
            if (stderr_fd >= 0 && success) {
                if ((descriptors[index].revents & (POLLIN | POLLHUP | POLLERR)) != 0
                    && !drain_stream(&stderr_fd, stderr_file, output_limit, &state->stderr_bytes, &state->stderr_truncated)) {
                    success = false;
                }
            }
        }

        if (!child_reaped) {
            pid_t waited = wait4(child, &child_status, WNOHANG, usage_out);
            if (waited == child) {
                child_reaped = true;
            } else if (waited < 0 && errno != EINTR) {
                success = false;
            }
        }
    }

    if (stdout_fd >= 0) {
        (void)close(stdout_fd);
    }
    if (stderr_fd >= 0) {
        (void)close(stderr_fd);
    }

    if (!child_reaped) {
        while (wait4(child, &child_status, 0, usage_out) < 0) {
            if (errno != EINTR) {
                success = false;
                break;
            }
        }
    }

    if (WIFEXITED(child_status)) {
        state->target_status = WEXITSTATUS(child_status);
    } else if (WIFSIGNALED(child_status)) {
        state->target_signal = WTERMSIG(child_status);
    } else {
        success = false;
    }

    *exec_errno_out = 0;
    return success;
}

static bool run_target(
    int memfd,
    char **target_argv,
    int stdout_file,
    int stderr_file,
    size_t output_limit,
    handoff_state *state,
    int *exec_errno_out)
{
    int stdout_pipe[2] = { -1, -1 };
    int stderr_pipe[2] = { -1, -1 };
    int exec_error_pipe[2] = { -1, -1 };
    if (pipe2(stdout_pipe, O_CLOEXEC) != 0
        || pipe2(stderr_pipe, O_CLOEXEC) != 0
        || pipe2(exec_error_pipe, O_CLOEXEC) != 0) {
        if (stdout_pipe[0] >= 0) {
            (void)close(stdout_pipe[0]);
            (void)close(stdout_pipe[1]);
        }
        if (stderr_pipe[0] >= 0) {
            (void)close(stderr_pipe[0]);
            (void)close(stderr_pipe[1]);
        }
        if (exec_error_pipe[0] >= 0) {
            (void)close(exec_error_pipe[0]);
            (void)close(exec_error_pipe[1]);
        }
        return false;
    }

    uint64_t started = monotonic_nanoseconds();
    pid_t child = fork();
    if (child < 0) {
        (void)close(stdout_pipe[0]);
        (void)close(stdout_pipe[1]);
        (void)close(stderr_pipe[0]);
        (void)close(stderr_pipe[1]);
        (void)close(exec_error_pipe[0]);
        (void)close(exec_error_pipe[1]);
        return false;
    }
    if (child == 0) {
        (void)close(stdout_pipe[0]);
        (void)close(stderr_pipe[0]);
        (void)close(exec_error_pipe[0]);
        if (dup2(stdout_pipe[1], STDOUT_FILENO) < 0 || dup2(stderr_pipe[1], STDERR_FILENO) < 0) {
            child_exec_failure child_error = { 0, errno };
            ssize_t error_bytes = write(exec_error_pipe[1], &child_error, sizeof(child_error));
            if (error_bytes < 0) {
                _exit(126);
            }
            _exit(126);
        }
        (void)close(stdout_pipe[1]);
        (void)close(stderr_pipe[1]);
        execveat(memfd, "", target_argv, environ, AT_EMPTY_PATH_VALUE);
        child_exec_failure child_error = { 1, errno };
        ssize_t error_bytes = write(exec_error_pipe[1], &child_error, sizeof(child_error));
        if (error_bytes < 0) {
            _exit(127);
        }
        _exit(127);
    }

    state->execveat_invoked = true;
    (void)close(exec_error_pipe[1]);
    struct rusage usage;
    memset(&usage, 0, sizeof(usage));
    bool captured = capture_child_streams(
        child,
        stdout_pipe,
        stderr_pipe,
        stdout_file,
        stderr_file,
        output_limit,
        state,
        exec_errno_out,
        &usage);
    child_exec_failure child_error = { -1, 0 };
    size_t child_exec_error_size = 0U;
    for (;;) {
        ssize_t count = read(exec_error_pipe[0], ((uint8_t *)&child_error) + child_exec_error_size,
            sizeof(child_error) - child_exec_error_size);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            break;
        }
        child_exec_error_size += (size_t)count;
        if (child_exec_error_size == sizeof(child_error)) {
            break;
        }
    }
    (void)close(exec_error_pipe[0]);
    state->execveat_invoked = child_exec_error_size == 0U || child_error.stage == 1;
    if (child_exec_error_size == sizeof(child_error) && child_error.stage == 1) {
        *exec_errno_out = child_error.error_number;
    }
    uint64_t ended = monotonic_nanoseconds();
    state->duration_ns = ended >= started ? ended - started : 0U;
    if (usage.ru_maxrss > 0) {
        uint64_t rss_kib = (uint64_t)usage.ru_maxrss;
        state->max_rss_bytes = rss_kib <= UINT64_MAX / 1024U ? rss_kib * 1024U : UINT64_MAX;
    }
    return captured;
}

static bool write_evidence(
    const char *path,
    const char *image_hash,
    const handoff_state *state,
    int helper_exit,
    bool passed)
{
    size_t path_length = strlen(path);
    if (path_length > SIZE_MAX - 48U) {
        return false;
    }
    size_t temporary_length = path_length + 48U;
    char *temporary = (char *)malloc(temporary_length);
    if (temporary == NULL) {
        return false;
    }
    int written = snprintf(temporary, temporary_length, "%s.%ld.tmp", path, (long)getpid());
    if (written < 0 || (size_t)written >= temporary_length) {
        free(temporary);
        return false;
    }

    int fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        free(temporary);
        return false;
    }

    char json[2048];
    const char *target_status = state->target_signal == 0 ? "" : "null";
    char target_status_value[32];
    if (state->target_signal == 0) {
        (void)snprintf(target_status_value, sizeof(target_status_value), "%d", state->target_status);
        target_status = target_status_value;
    }
    const char *signal_value = state->target_signal == 0 ? "null" : NULL;
    char target_signal_value[32];
    if (state->target_signal != 0) {
        (void)snprintf(target_signal_value, sizeof(target_signal_value), "%d", state->target_signal);
        signal_value = target_signal_value;
    }
    char escaped_diagnostic[512];
    const char *diagnostic = state->diagnostic == NULL ? "" : state->diagnostic;
    if (!json_escape(diagnostic, escaped_diagnostic, sizeof(escaped_diagnostic))) {
        (void)close(fd);
        (void)unlink(temporary);
        free(temporary);
        return false;
    }
    int json_length = snprintf(
        json,
        sizeof(json),
        "{\n"
        "  \"schemaVersion\": 1,\n"
        "  \"stage\": \"native-handoff\",\n"
        "  \"status\": \"%s\",\n"
        "  \"helperStatus\": \"%s\",\n"
        "  \"helperExitCode\": %d,\n"
        "  \"nativeImageSha256\": \"%s\",\n"
        "  \"rehydrationRecordSha256\": \"%s\",\n"
        "  \"loaderId\": \"kernel.execveat-at-empty-path\",\n"
        "  \"memfdCreated\": %s,\n"
        "  \"fchmodStatus\": \"%s\",\n"
        "  \"fsyncStatus\": \"%s\",\n"
        "  \"sealsSupported\": %s,\n"
        "  \"sealsApplied\": %s,\n"
        "  \"execveatInvoked\": %s,\n"
        "  \"execveatStatus\": \"%s\",\n"
        "  \"targetStatus\": %s,\n"
        "  \"targetSignal\": %s,\n"
        "  \"stdoutBytes\": %" PRIu64 ",\n"
        "  \"stderrBytes\": %" PRIu64 ",\n"
        "  \"stdoutTruncated\": %s,\n"
        "  \"stderrTruncated\": %s,\n"
        "  \"targetDurationNanoseconds\": %" PRIu64 ",\n"
        "  \"maxRssBytes\": %" PRIu64 ",\n"
        "  \"firstFailureStage\": %s,\n"
        "  \"diagnostic\": \"%s\"\n"
        "}\n",
        passed ? "passed" : "failed",
        passed ? "passed" : "failed",
        helper_exit,
        image_hash == NULL ? "" : image_hash,
        state->rehydration_record_sha256 == NULL ? "" : state->rehydration_record_sha256,
        state->memfd_created ? "true" : "false",
        state->fchmod_passed ? "passed" : "failed",
        state->fsync_passed ? "passed" : "failed",
        state->seals_supported ? "true" : "false",
        state->seals_applied ? "true" : "false",
        state->execveat_invoked ? "true" : "false",
        state->execveat_passed ? "passed" : "failed",
        target_status,
        signal_value,
        state->stdout_bytes,
        state->stderr_bytes,
        state->stdout_truncated ? "true" : "false",
        state->stderr_truncated ? "true" : "false",
        state->duration_ns,
        state->max_rss_bytes,
        passed ? "null" : "\"native-handoff\"",
        escaped_diagnostic);
    bool success = json_length > 0 && (size_t)json_length < sizeof(json)
        && write_all(fd, (const uint8_t *)json, (size_t)json_length)
        && fsync(fd) == 0;
    if (close(fd) != 0) {
        success = false;
    }
    if (success && rename(temporary, path) != 0) {
        success = false;
    }
    if (!success) {
        (void)unlink(temporary);
    }
    free(temporary);
    return success;
}

static int fail_with_evidence(
    const char *evidence_path,
    const char *image_hash,
    handoff_state *state,
    int exit_code,
    const char *diagnostic)
{
    state->diagnostic = diagnostic;
    if (!write_evidence(evidence_path, image_hash, state, exit_code, false)) {
        return 68;
    }
    return exit_code;
}

int main(int argc, char **argv)
{
    handoff_state state;
    memset(&state, 0, sizeof(state));
    state.target_status = -1;
    int helper_exit = 64;
    char image_hash[65] = "";

    if (argc < 10 || strcmp(argv[8], "--") != 0) {
        fprintf(stderr, "usage: %s IMAGE EXPECTED_SHA256 REHYDRATION_SHA256 EVIDENCE_JSON STDOUT_FILE STDERR_FILE OUTPUT_LIMIT -- ARG0 [ARG ...]\n", argv[0]);
        return 64;
    }
    const char *image_path = argv[1];
    const char *expected_hash = argv[2];
    const char *rehydration_hash = argv[3];
    const char *evidence_path = argv[4];
    const char *stdout_path = argv[5];
    const char *stderr_path = argv[6];
    size_t output_limit = 0U;
    if (!is_hex_digest(expected_hash) || !is_hex_digest(rehydration_hash)
        || !parse_limit(argv[7], &output_limit)
        || (size_t)(argc - 9) > MAX_ARGUMENTS) {
        state.diagnostic = "InvalidArguments";
        (void)write_evidence(evidence_path, image_hash, &state, helper_exit, false);
        return helper_exit;
    }
    state.rehydration_record_sha256 = rehydration_hash;

    size_t argument_bytes = 0U;
    for (int index = 9; index < argc; ++index) {
        size_t argument_length = strlen(argv[index]);
        if (argument_length > MAX_ARGUMENT_BYTES - argument_bytes) {
            return fail_with_evidence(evidence_path, image_hash, &state, 64, "TargetArgumentsOutOfBounds");
        }
        argument_bytes += argument_length;
    }

    int stdout_file = open_capture(stdout_path);
    int stderr_file = open_capture(stderr_path);
    if (stdout_file < 0 || stderr_file < 0) {
        if (stdout_file >= 0) {
            (void)close(stdout_file);
        }
        if (stderr_file >= 0) {
            (void)close(stderr_file);
        }
        return fail_with_evidence(evidence_path, image_hash, &state, 65, "StreamCaptureOpenFailed");
    }

    int source_fd = open(image_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat information;
    if (source_fd < 0 || fstat(source_fd, &information) != 0
        || !S_ISREG(information.st_mode) || information.st_size <= 0
        || (uint64_t)information.st_size > (uint64_t)MAX_IMAGE_BYTES
        || (uint64_t)information.st_size > (uint64_t)SIZE_MAX) {
        if (source_fd >= 0) {
            (void)close(source_fd);
        }
        (void)close(stdout_file);
        (void)close(stderr_file);
        return fail_with_evidence(evidence_path, image_hash, &state, 65, "NativeImageInputInvalid");
    }

    size_t image_size = (size_t)information.st_size;
    uint8_t *image_bytes = (uint8_t *)malloc(image_size);
    if (image_bytes == NULL) {
        (void)close(source_fd);
        (void)close(stdout_file);
        (void)close(stderr_file);
        return fail_with_evidence(evidence_path, image_hash, &state, 65, "NativeImageAllocationFailed");
    }
    size_t image_offset = 0U;
    while (image_offset < image_size) {
        ssize_t count = read(source_fd, image_bytes + image_offset, image_size - image_offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            free(image_bytes);
            (void)close(source_fd);
            (void)close(stdout_file);
            (void)close(stderr_file);
            return fail_with_evidence(evidence_path, image_hash, &state, 65, "NativeImageReadFailed");
        }
        image_offset += (size_t)count;
    }
    (void)close(source_fd);

    uint8_t digest[32];
    urp_sha256_context hash_context;
    urp_sha256_init(&hash_context);
    urp_sha256_update(&hash_context, image_bytes, image_size);
    urp_sha256_final(&hash_context, digest);
    digest_hex(digest, image_hash);
    if (!digest_matches(expected_hash, image_hash)) {
        free(image_bytes);
        (void)close(stdout_file);
        (void)close(stderr_file);
        return fail_with_evidence(evidence_path, image_hash, &state, 65, "NativeImageDigestMismatch");
    }

    int memfd = memfd_create("urprotect-native-image", MEMFD_FLAGS);
    if (memfd < 0) {
        free(image_bytes);
        (void)close(stdout_file);
        (void)close(stderr_file);
        return fail_with_evidence(evidence_path, image_hash, &state, 66, "MemfdCreateFailed");
    }
    state.memfd_created = true;
    if (!copy_image_to_memfd(source_fd, memfd, image_bytes, image_size)) {
        free(image_bytes);
        (void)close(memfd);
        (void)close(stdout_file);
        (void)close(stderr_file);
        return fail_with_evidence(evidence_path, image_hash, &state, 66, "MemfdWriteFailed");
    }
    free(image_bytes);
    if (fchmod(memfd, S_IRUSR | S_IWUSR | S_IXUSR) != 0) {
        (void)close(memfd);
        (void)close(stdout_file);
        (void)close(stderr_file);
        return fail_with_evidence(evidence_path, image_hash, &state, 66, "MemfdFchmodFailed");
    }
    state.fchmod_passed = true;
    if (fsync(memfd) != 0) {
        (void)close(memfd);
        (void)close(stdout_file);
        (void)close(stderr_file);
        return fail_with_evidence(evidence_path, image_hash, &state, 66, "MemfdFsyncFailed");
    }
    state.fsync_passed = true;

#ifdef F_ADD_SEALS
    state.seals_supported = true;
    if (fcntl(memfd, F_ADD_SEALS, REQUIRED_SEALS) != 0) {
        state.seals_supported = false;
        (void)close(memfd);
        (void)close(stdout_file);
        (void)close(stderr_file);
        return fail_with_evidence(evidence_path, image_hash, &state, 66, "MemfdSealFailed");
    }
    int seals = fcntl(memfd, F_GET_SEALS);
    if (seals < 0 || (seals & REQUIRED_SEALS) != REQUIRED_SEALS) {
        (void)close(memfd);
        (void)close(stdout_file);
        (void)close(stderr_file);
        return fail_with_evidence(evidence_path, image_hash, &state, 66, "MemfdSealVerificationFailed");
    }
    state.seals_applied = true;
#else
    (void)close(memfd);
    (void)close(stdout_file);
    (void)close(stderr_file);
    return fail_with_evidence(evidence_path, image_hash, &state, 66, "MemfdSealsUnavailable");
#endif

    int exec_errno = 0;
    char **target_argv = &argv[9];
    bool target_captured = run_target(memfd, target_argv, stdout_file, stderr_file, output_limit, &state, &exec_errno);
    state.execveat_passed = target_captured && state.execveat_invoked && exec_errno == 0;
    (void)close(memfd);
    (void)close(stdout_file);
    (void)close(stderr_file);
    if (!target_captured) {
        state.diagnostic = "TargetCaptureFailed";
        helper_exit = 67;
    } else if (!state.execveat_passed) {
        state.diagnostic = "ExecveatFailed";
        helper_exit = 67;
    } else {
        state.diagnostic = "";
        helper_exit = 0;
    }
    bool evidence_written = write_evidence(evidence_path, image_hash, &state, helper_exit, helper_exit == 0);
    return evidence_written ? helper_exit : 68;
}
