#define _GNU_SOURCE
#include "urp/host_adapter.h"
#include "urp/runtime.h"

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char **environ;

typedef struct dispatch_state {
    const uint8_t *wrapper;
    size_t wrapper_size;
    const urp_host_context_v1 *host;
    const urp_launch_args_v1 *args;
    urp_status status;
} dispatch_state;

static void *dispatch(void *opaque)
{
    dispatch_state *state = opaque;
    state->status = urp_runtime_execute_wrapper(
        state->host, state->wrapper, state->wrapper_size, state->args);
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    FILE *file = fopen(argv[1], "rb");
    if (file == NULL || fseek(file, 0, SEEK_END) != 0) return 3;
    long end = ftell(file);
    if (end <= 0 || fseek(file, 0, SEEK_SET) != 0) return 4;
    size_t size = (size_t)end;
    uint8_t *wrapper = malloc(size);
    if (wrapper == NULL || fread(wrapper, 1U, size, file) != size) return 5;
    fclose(file);

    int events[2], gates[2];
    if (pipe(events) != 0 || pipe(gates) != 0) return 6;
    char event_fd[24], gate_fd[24];
    (void)snprintf(event_fd, sizeof(event_fd), "%d", events[1]);
    (void)snprintf(gate_fd, sizeof(gate_fd), "%d", gates[0]);
    (void)setenv("URP_TLS_EVENT_FD", event_fd, 1);
    (void)setenv("URP_TLS_GATE_FD", gate_fd, 1);
    (void)setenv("URP_TLS_JOIN_MODE", "automatic", 1);

    urp_host_adapter_v1 adapter;
    urp_host_adapter_init(&adapter);
    if ((adapter.context.capabilities & URP_HOST_CAP_THREAD_LIFETIME) == 0U) return 7;
    const char *launch_argv[] = { "threaded-runtime-test", NULL };
    const urp_launch_args_v1 launch_args = {
        .abi_version = URP_HOST_ABI_VERSION,
        .struct_size = URP_LAUNCH_ARGS_CURRENT_SIZE,
        .argc = 1U,
        .argv = launch_argv,
        .envp = (const char *const *)environ,
        .image = 0U,
    };
    dispatch_state states[2] = {
        { wrapper, size, &adapter.context, &launch_args, URP_STATUS_LOAD_FAILED },
        { wrapper, size, &adapter.context, &launch_args, URP_STATUS_LOAD_FAILED },
    };
    pthread_t dispatch_threads[2];
    if (pthread_create(&dispatch_threads[0], NULL, dispatch, &states[0]) != 0
        || pthread_create(&dispatch_threads[1], NULL, dispatch, &states[1]) != 0) return 8;

    char markers[4096];
    size_t used = 0U;
    unsigned starts = 0U;
    while (starts < 2U && used + 1U < sizeof(markers)) {
        struct pollfd descriptor = { .fd = events[0], .events = POLLIN };
        if (poll(&descriptor, 1U, 10000) <= 0) return 9;
        ssize_t count = read(events[0], markers + used, sizeof(markers) - used - 1U);
        if (count <= 0) return 10;
        used += (size_t)count;
        markers[used] = '\0';
        starts = 0U;
        const char *cursor = markers;
        while ((cursor = strstr(cursor, "worker-start tls=4660 zero=0\n")) != NULL) {
            ++starts;
            cursor++;
        }
    }
    const char release[2] = { 'a', 'b' };
    if (write(gates[1], release, sizeof(release)) != (ssize_t)sizeof(release)) return 11;
    close(gates[1]);
    for (size_t index = 0U; index < 2U; ++index) {
        if (pthread_join(dispatch_threads[index], NULL) != 0 || states[index].status != 61)
            return 12;
    }
    close(events[1]);
    while (used + 1U < sizeof(markers)) {
        ssize_t count = read(events[0], markers + used, sizeof(markers) - used - 1U);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        used += (size_t)count;
        markers[used] = '\0';
    }
    close(events[0]);
    /* Completion, TLS teardown, and loader destructor are independently observed twice. */
    const char *twice[] = { "worker-complete tls=4660 zero=22136\n", "tls-teardown\n", "destructor\n" };
    for (size_t item = 0U; item < sizeof(twice) / sizeof(twice[0]); ++item) {
        unsigned count = 0U;
        const char *cursor = markers;
        while ((cursor = strstr(cursor, twice[item])) != NULL) { ++count; cursor++; }
        if (count != 2U) return 13;
    }
    printf("concurrent_dispatches=2 statuses=61,61 workers=2 tls_instances=distinct-image-and-thread release_order=verified\n%s", markers);
    free(wrapper);
    return 0;
}
