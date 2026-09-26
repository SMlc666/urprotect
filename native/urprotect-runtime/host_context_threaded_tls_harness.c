#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int run_once(const char *wrapper, const char *mode)
{
    int events[2], gate[2];
    if (pipe(events) != 0 || pipe(gate) != 0) return 10;
    pid_t child = fork();
    if (child < 0) return 11;
    if (child == 0) {
        close(events[0]); close(gate[1]);
        if (dup2(events[1], 198) < 0 || dup2(gate[0], 199) < 0) _exit(120);
        close(events[1]); close(gate[0]);
        (void)setenv("URP_TLS_EVENT_FD", "198", 1);
        (void)setenv("URP_TLS_GATE_FD", "199", 1);
        (void)setenv("URP_TLS_JOIN_MODE", mode, 1);
        if (strcmp(mode, "failure") == 0) (void)setenv("URP_TLS_ENTRY_FAIL", "1", 1);
        execl(wrapper, wrapper, (char *)NULL);
        _exit(121);
    }
    close(events[1]); close(gate[0]);
    char output[1024];
    size_t used = 0U;
    int started = 0;
    while (used + 1U < sizeof(output)) {
        struct pollfd descriptor = { .fd = events[0], .events = POLLIN };
        if (poll(&descriptor, 1U, 10000) <= 0) break;
        ssize_t count = read(events[0], output + used, sizeof(output) - used - 1U);
        if (count <= 0) break;
        used += (size_t)count;
        output[used] = '\0';
        if (strstr(output, "worker-start tls=4660 zero=0\n") != NULL
            && strstr(output, "entry-tls-isolated zero=17185\n") != NULL) {
            started = 1;
            break;
        }
    }
    int state = 0;
    if (!started || waitpid(child, &state, WNOHANG) != 0) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, &state, 0);
        return 12;
    }
    const char gates[1] = { 'x' };
    if (write(gate[1], gates, sizeof(gates)) != (ssize_t)sizeof(gates)) return 13;
    close(gate[1]);
    for (;;) {
        struct pollfd descriptor = { .fd = events[0], .events = POLLIN };
        int ready = poll(&descriptor, 1U, 10000);
        if (ready <= 0) break;
        ssize_t count = read(events[0], output + used, sizeof(output) - used - 1U);
        if (count <= 0) break;
        used += (size_t)count;
        output[used] = '\0';
    }
    close(events[0]);
    int expected_status = strcmp(mode, "failure") == 0 ? 4 : 61;
    if (waitpid(child, &state, 0) != child || !WIFEXITED(state) || WEXITSTATUS(state) != expected_status)
        return 14;
    const char *required[] = { "constructor\n", "entry-tls data=4660 zero=0\n", "entry\n",
        "entry-tls-isolated zero=17185\n", "worker-start tls=4660 zero=0\n",
        "worker-complete tls=4660 zero=22136\n", "tls-teardown\n", "destructor\n" };
    size_t last = 0U;
    for (size_t i = 0U; i < sizeof(required) / sizeof(required[0]); ++i) {
        char *found = strstr(output + last, required[i]);
        if (found == NULL) {
            fprintf(stderr, "missing marker: %s\nobserved:\n%s", required[i], output);
            return 15;
        }
        last = (size_t)(found - output) + strlen(required[i]);
    }
    if (strcmp(mode, "explicit") == 0 && strstr(output, "entry-joined\n") == NULL) return 16;
    printf("mode=%s status=%d markers=ordered\n%s", mode, expected_status, output);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    int status = run_once(argv[1], "automatic");
    if (status != 0) return status;
    status = run_once(argv[1], "explicit");
    if (status != 0) return status;
    return run_once(argv[1], "failure");
}
