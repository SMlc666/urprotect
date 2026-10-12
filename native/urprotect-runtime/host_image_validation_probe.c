#include "host_image_validation.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#define MAX_IMAGE_BYTES (128U * 1024U * 1024U)

static int read_image(const char *path, uint8_t **bytes_out, size_t *size_out)
{
    FILE *stream = NULL;
    struct stat info;
    uint8_t *bytes = NULL;
    size_t size;
    size_t offset = 0U;

    if (path == NULL || bytes_out == NULL || size_out == NULL
        || stat(path, &info) != 0 || !S_ISREG(info.st_mode)
        || info.st_size <= 0 || (uint64_t)info.st_size > MAX_IMAGE_BYTES
        || (uint64_t)info.st_size > (uint64_t)SIZE_MAX) {
        return 0;
    }

    size = (size_t)info.st_size;
    bytes = (uint8_t *)malloc(size);
    if (bytes == NULL) {
        return 0;
    }

    stream = fopen(path, "rb");
    if (stream == NULL) {
        free(bytes);
        return 0;
    }
    while (offset < size) {
        size_t count = fread(bytes + offset, 1U, size - offset, stream);
        if (count == 0U) {
            if (ferror(stream) != 0) {
                (void)fclose(stream);
                free(bytes);
                return 0;
            }
            break;
        }
        offset += count;
    }
    if (fclose(stream) != 0 || offset != size) {
        free(bytes);
        return 0;
    }

    *bytes_out = bytes;
    *size_out = size;
    return 1;
}

int main(int argc, char **argv)
{
    uint8_t *bytes = NULL;
    size_t size = 0U;
    size_t dependency_count = 0U;
    urp_status status;

    if (argc != 2 || !read_image(argv[1], &bytes, &size)) {
        return 2;
    }

    status = urp_host_image_validate(bytes, size, &dependency_count);
    (void)printf(
        "{\"schemaVersion\":1,\"status\":%" PRId32 ",\"dependencyCount\":%zu}\n",
        status,
        dependency_count);
    free(bytes);
    return 0;
}
