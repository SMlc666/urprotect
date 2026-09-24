#include "urp/host_context.h"

#include <stdint.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

static volatile int dependency_constructor_ran;

__attribute__((constructor)) static void dependency_constructor(void)
{
    dependency_constructor_ran = 1;
}

__attribute__((destructor)) static void dependency_destructor(void)
{
    const char *marker = getenv("URP_LIFECYCLE_MARKER");
    if (marker == 0) {
        return;
    }
    int fd = open(marker, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        static const char released[] = "released\n";
        ssize_t written = write(fd, released, sizeof(released) - 1U);
        (void)written;
        (void)close(fd);
    }
}

int32_t urp_entry(
    const urp_host_context_v1 *host,
    const urp_launch_args_v1 *args)
{
    if (host == 0 || args == 0 || args->argc != 1U || args->argv == 0) {
        return 19;
    }
    return dependency_constructor_ran != 0 && getpid() > 0 ? 37 : 39;
}
