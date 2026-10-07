#define _GNU_SOURCE

#include "urp/host_adapter.h"
#include "sha256.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_IMAGE_BYTES (128U * 1024U * 1024U)

extern char **environ;

static int read_image(const char *path, uint8_t **bytes_out, size_t *size_out)
{
    int fd = -1;
    struct stat info;
    uint8_t *bytes = NULL;
    size_t size;
    size_t offset = 0U;
    if (path == NULL || bytes_out == NULL || size_out == NULL) return 0;
    *bytes_out = NULL;
    *size_out = 0U;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &info) != 0 || !S_ISREG(info.st_mode)
        || info.st_size <= 0 || (uint64_t)info.st_size > MAX_IMAGE_BYTES
        || (uint64_t)info.st_size > (uint64_t)SIZE_MAX) {
        if (fd >= 0) (void)close(fd);
        return 0;
    }
    size = (size_t)info.st_size;
    bytes = (uint8_t *)malloc(size);
    if (bytes == NULL) {
        (void)close(fd);
        return 0;
    }
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
    (void)close(fd);
    *bytes_out = bytes;
    *size_out = size;
    return 1;
}

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

static int write_record(
    const char *path,
    const char *status,
    const char *image_hash,
    const char *entry_symbol,
    int entry_status,
    const char *release_status,
    const char *first_failure)
{
    char temporary[4096];
    int result;
    if (path == NULL || status == NULL || image_hash == NULL || entry_symbol == NULL
        || release_status == NULL || first_failure == NULL
        || strlen(path) >= sizeof(temporary) - 8U) {
        return 0;
    }
    result = snprintf(temporary, sizeof(temporary), "%s.tmp", path);
    if (result < 0 || (size_t)result >= sizeof(temporary)) return 0;
    FILE *stream = fopen(temporary, "w");
    if (stream == NULL) return 0;
    (void)fprintf(
        stream,
        "{\n"
        "  \"schemaVersion\": 1,\n"
        "  \"stage\": \"host-context-handoff\",\n"
        "  \"status\": \"%s\",\n"
        "  \"loaderId\": \"host-context.sealed-memfd.dlopen\",\n"
        "  \"nativeImageSha256\": \"%s\",\n"
        "  \"entrySymbol\": \"%s\",\n"
        "  \"entryStatus\": %d,\n"
        "  \"releaseStatus\": \"%s\",\n"
        "  \"releaseOrder\": \"entry-dispatch-before-release-image\",\n"
        "  \"firstFailureStage\": %s\n"
        "}\n",
        status,
        image_hash,
        entry_symbol,
        entry_status,
        release_status,
        strcmp(first_failure, "null") == 0 ? "null" : "\"host-context-handoff\"");
    if (fclose(stream) != 0 || rename(temporary, path) != 0) {
        (void)unlink(temporary);
        return 0;
    }
    return 1;
}

int main(int argc, char **argv)
{
    const char *image_path;
    const char *entry_symbol;
    const char *record_path;
    uint8_t *image = NULL;
    size_t image_size = 0U;
    char image_hash[65] = {0};
    urp_host_adapter_v1 adapter;
    urp_image_handle handle = 0U;
    uintptr_t entry_address = 0U;
    urp_entry_fn entry;
    const char *entry_argv[] = { "fixture", NULL };
    urp_launch_args_v1 launch_args;
    int32_t entry_status = -1;
    urp_status release_status = URP_STATUS_LOAD_FAILED;
    const char *status = "failed";
    const char *release_status_text = "not-run";
    const char *first_failure = "host-context-handoff";
    int exit_status = 1;

    if (argc != 4) return 2;
    image_path = argv[1];
    entry_symbol = argv[2];
    record_path = argv[3];
    if (!read_image(image_path, &image, &image_size)) return 1;
    digest_hex(image, image_size, image_hash);
    urp_host_adapter_init(&adapter);
    if (adapter.context.load_image(
            adapter.context.userdata,
            image,
            image_size,
            URP_LOAD_IMAGE_IMMUTABLE,
            &handle) != URP_STATUS_OK
        || handle == 0U) {
        (void)write_record(record_path, status, image_hash, entry_symbol, -1, release_status_text, first_failure);
        free(image);
        return 1;
    }
    if (adapter.context.lookup_symbol(
            adapter.context.userdata,
            handle,
            entry_symbol,
            NULL,
            &entry_address) != URP_STATUS_OK
        || entry_address == 0U) {
        (void)adapter.context.release_image(adapter.context.userdata, handle);
        (void)write_record(record_path, status, image_hash, entry_symbol, -1, "passed", first_failure);
        free(image);
        return 1;
    }
    memcpy(&entry, &entry_address, sizeof(entry));
    launch_args.abi_version = URP_HOST_ABI_VERSION;
    launch_args.struct_size = URP_LAUNCH_ARGS_MIN_SIZE;
    launch_args.argc = 1U;
    launch_args.argv = entry_argv;
    launch_args.envp = (const char *const *)environ;
    launch_args.image = 0U;
    entry_status = entry(&adapter.context, &launch_args);
    release_status = adapter.context.release_image(adapter.context.userdata, handle);
    release_status_text = release_status == URP_STATUS_OK ? "passed" : "failed";
    if (release_status == URP_STATUS_OK) {
        status = "passed";
        first_failure = "null";
        exit_status = entry_status < 0 ? 1 : entry_status > 255 ? 255 : entry_status;
    }
    (void)write_record(
        record_path,
        status,
        image_hash,
        entry_symbol,
        entry_status,
        release_status_text,
        first_failure);
    free(image);
    return exit_status;
}
