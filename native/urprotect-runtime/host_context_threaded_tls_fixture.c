#define _GNU_SOURCE
#include "urp/host_context.h"

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__thread uint32_t urp_thread_tls_data = UINT32_C(0x1234);
__thread uint32_t urp_thread_tls_zero;
static pthread_key_t urp_tls_key;
static int urp_event_fd = -1;
static int urp_gate_fd = -1;

static int urp_env_fd(const char *name)
{
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') return -1;
    char *end = NULL;
    long parsed = strtol(value, &end, 10);
    return end != value && *end == '\0' && parsed >= 0 && parsed <= 1048576
        ? (int)parsed : -1;
}

static void urp_event(const char *message)
{
    if (urp_event_fd < 0) return;
    size_t size = strlen(message);
    while (size != 0U) {
        ssize_t written = write(urp_event_fd, message, size);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return;
        message += written;
        size -= (size_t)written;
    }
}

static void urp_tls_destructor(void *value)
{
    (void)value;
    urp_event("tls-teardown\n");
}

static void urp_constructor(void) __attribute__((constructor));
static void urp_constructor(void)
{
    urp_event_fd = urp_env_fd("URP_TLS_EVENT_FD");
    urp_gate_fd = urp_env_fd("URP_TLS_GATE_FD");
    if (pthread_key_create(&urp_tls_key, urp_tls_destructor) == 0)
        urp_event("constructor\n");
}

static void urp_destructor(void) __attribute__((destructor));
static void urp_destructor(void)
{
    urp_event("destructor\n");
    (void)pthread_key_delete(urp_tls_key);
}

static void *urp_worker(void *unused)
{
    (void)unused;
    if (urp_thread_tls_data != UINT32_C(0x1234) || urp_thread_tls_zero != 0U)
        return (void *)(uintptr_t)1U;
    urp_thread_tls_zero = UINT32_C(0x5678);
    if (pthread_setspecific(urp_tls_key, (void *)(uintptr_t)1U) != 0)
        return (void *)(uintptr_t)2U;
    urp_event("worker-start tls=4660 zero=0\n");
    char gate = 0;
    for (;;) {
        ssize_t count = read(urp_gate_fd, &gate, 1U);
        if (count < 0 && errno == EINTR) continue;
        if (count != 1) return (void *)(uintptr_t)3U;
        break;
    }
    urp_event("worker-complete tls=4660 zero=22136\n");
    return (void *)(uintptr_t)0x55U;
}

int32_t urp_entry(const urp_host_context_v1 *host, const urp_launch_args_v1 *args)
{
    if (host == NULL || args == NULL || args->argc != 1U || args->argv == NULL
        || args->struct_size != URP_LAUNCH_ARGS_CURRENT_SIZE || args->image == 0U
        || (host->capabilities & URP_HOST_CAP_THREAD_LIFETIME) == 0U
        || host->struct_size < URP_HOST_CONTEXT_THREAD_LIFETIME_SIZE
        || host->create_image_thread == NULL || host->join_image_thread == NULL)
        return 71;
    if (urp_thread_tls_data != UINT32_C(0x1234) || urp_thread_tls_zero != 0U)
        return 72;
    urp_event("entry-tls data=4660 zero=0\n");
    urp_thread_tls_zero = UINT32_C(0x4321);
    urp_event("entry\n");
    urp_image_thread_handle thread = 0U;
    if (host->create_image_thread(host->userdata, args->image, urp_worker, NULL, &thread) != URP_STATUS_OK
        || thread == 0U)
        return 73;
    /* The worker writes its own TLS instance; the dispatch thread retains its
     * independent value even while the registered worker is alive. */
    if (urp_thread_tls_zero != UINT32_C(0x4321)) return 75;
    urp_event("entry-tls-isolated zero=17185\n");
    const char *mode = getenv("URP_TLS_JOIN_MODE");
    if (mode != NULL && strcmp(mode, "explicit") == 0) {
        void *result = NULL;
        if (host->join_image_thread(host->userdata, args->image, thread, &result) != URP_STATUS_OK
            || result != (void *)(uintptr_t)0x55U)
            return 74;
        urp_event("entry-joined\n");
    }
    const char *fail = getenv("URP_TLS_ENTRY_FAIL");
    if (fail != NULL && strcmp(fail, "1") == 0) return -77;
    return 61;
}

/* Adapter-contract probe: exported only so the self-test can verify root ownership. */
void *urp_thread_test_worker(void *argument)
{
    return argument;
}

struct urp_self_join_probe {
    const urp_host_context_v1 *host;
    urp_image_handle image;
    uint64_t thread;
    urp_status status;
};

void *urp_thread_self_join_worker(void *opaque)
{
    struct urp_self_join_probe *probe = opaque;
    uint64_t thread;
    while ((thread = __atomic_load_n(&probe->thread, __ATOMIC_ACQUIRE)) == 0U)
        (void)sched_yield();
    void *result = NULL;
    urp_status status = probe->host->join_image_thread(
        probe->host->userdata, probe->image, thread, &result);
    __atomic_store_n(&probe->status, status, __ATOMIC_RELEASE);
    return NULL;
}
