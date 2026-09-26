#define _GNU_SOURCE

#include "host_context_graph_fixture_contract.h"

#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2) {
        return 2;
    }
    if (unlink(URP_FAKE_LOADER_MARKER_PATH) != 0 && errno != ENOENT) {
        return 1;
    }

    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        (void)fprintf(stderr, "fake-loader probe dlopen failed: %s\n", dlerror());
        return 1;
    }

    FILE *marker = fopen(URP_FAKE_LOADER_MARKER_PATH, "rb");
    char contents[64] = {0};
    int valid = marker != NULL
        && fgets(contents, (int)sizeof(contents), marker) != NULL
        && strcmp(contents, "fake-loader-loaded\n") == 0;
    if (marker != NULL && fclose(marker) != 0) {
        valid = 0;
    }
    (void)dlclose(handle);
    (void)unlink(URP_FAKE_LOADER_MARKER_PATH);
    if (!valid) {
        (void)fputs("fake-loader constructor marker was not observed\n", stderr);
        return 1;
    }
    (void)puts("fake-loader probe: PASS");
    return 0;
}
