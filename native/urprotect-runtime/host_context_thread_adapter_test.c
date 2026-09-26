#define _GNU_SOURCE
#include "urp/host_adapter.h"
#include <stdint.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef void *(*worker_fn)(void *);
typedef struct foreign_call_state {
    urp_host_adapter_v1 *adapter;
    urp_image_handle image;
    urp_image_thread_handle thread;
    worker_fn routine;
    urp_status create_status;
    urp_status join_status;
    urp_status release_status;
    urp_image_thread_handle published;
} foreign_call_state;

static void *foreign_owner_calls(void *opaque)
{
    foreign_call_state *state = opaque;
    state->create_status = state->adapter->context.create_image_thread(
        state->adapter->context.userdata, state->image, state->routine, NULL, &state->published);
    void *result = NULL;
    state->join_status = state->adapter->context.join_image_thread(
        state->adapter->context.userdata, state->image, state->thread, &result);
    state->release_status = state->adapter->context.release_image(
        state->adapter->context.userdata, state->image);
    return NULL;
}

static int expect(int condition, const char *message)
{
    if (!condition) fprintf(stderr, "thread adapter test: %s\n", message);
    return condition;
}

static int read_bytes(const char *path, void **bytes_out, size_t *size_out)
{
    FILE *input = fopen(path, "rb");
    if (input == NULL || fseek(input, 0, SEEK_END) != 0) return 0;
    long end = ftell(input);
    if (end <= 0 || fseek(input, 0, SEEK_SET) != 0) return 0;
    size_t size = (size_t)end;
    void *bytes = malloc(size);
    if (bytes == NULL || fread(bytes, 1U, size, input) != size) return 0;
    fclose(input);
    *bytes_out = bytes;
    *size_out = size;
    return 1;
}

int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    FILE *input = fopen(argv[1], "rb");
    if (input == NULL || fseek(input, 0, SEEK_END) != 0) return 3;
    long end = ftell(input);
    if (end <= 0 || fseek(input, 0, SEEK_SET) != 0) return 4;
    size_t size = (size_t)end;
    void *bytes = malloc(size);
    if (bytes == NULL || fread(bytes, 1U, size, input) != size) return 5;
    fclose(input);
    urp_host_adapter_v1 adapter;
    urp_host_adapter_init(&adapter);
    if ((adapter.context.capabilities & URP_HOST_CAP_THREAD_LIFETIME) == 0U) {
        if (!expect(adapter.context.create_image_thread == NULL
                && adapter.context.join_image_thread == NULL,
                "non-glibc runtime advertised thread callbacks")) return 6;
        void *dynamic_bytes = NULL;
        size_t dynamic_size = 0U;
        if (!read_bytes(argv[2], &dynamic_bytes, &dynamic_size)) return 24;
        size_t attempts_before = urp_host_adapter_memfd_create_attempts();
        urp_image_handle dynamic_image = UINT64_C(0xfeedface);
        urp_status dynamic_status = adapter.context.load_image(adapter.context.userdata,
            dynamic_bytes, dynamic_size, URP_LOAD_IMAGE_IMMUTABLE, &dynamic_image);
        free(dynamic_bytes);
        if (!expect(dynamic_status == URP_STATUS_UNSUPPORTED && dynamic_image == 0U
                && urp_host_adapter_memfd_create_attempts() == attempts_before,
                "dynamic TLS reached memfd or returned a live image on non-glibc")) return 25;
        puts("non-glibc thread-lifetime capability absent; dynamic TLS rejection: PASS");
        return 0;
    }
    urp_image_handle image = 0U;
    if (adapter.context.load_image(adapter.context.userdata, bytes, size,
            URP_LOAD_IMAGE_IMMUTABLE, &image) != URP_STATUS_OK || image == 0U) return 7;
    free(bytes);
    uintptr_t raw = 0U;
    if (adapter.context.lookup_symbol(adapter.context.userdata, image,
            "urp_thread_test_worker", NULL, &raw) != URP_STATUS_OK || raw == 0U) return 8;
    worker_fn routine = NULL;
    memcpy(&routine, &raw, sizeof(routine));
    urp_image_handle second_image = 0U;
    FILE *second_input = fopen(argv[1], "rb");
    if (second_input == NULL || fseek(second_input, 0, SEEK_END) != 0) return 9;
    long second_end = ftell(second_input);
    if (second_end <= 0 || fseek(second_input, 0, SEEK_SET) != 0) return 10;
    size_t second_size = (size_t)second_end;
    void *second_bytes = malloc(second_size);
    if (second_bytes == NULL || fread(second_bytes, 1U, second_size, second_input) != second_size) return 11;
    fclose(second_input);
    if (adapter.context.load_image(adapter.context.userdata, second_bytes, second_size,
            URP_LOAD_IMAGE_IMMUTABLE, &second_image) != URP_STATUS_OK) return 12;
    free(second_bytes);
    uintptr_t second_raw = 0U;
    if (adapter.context.lookup_symbol(adapter.context.userdata, second_image,
            "urp_thread_test_worker", NULL, &second_raw) != URP_STATUS_OK) return 13;
    worker_fn second_routine = NULL;
    memcpy(&second_routine, &second_raw, sizeof(second_routine));
    urp_image_thread_handle second_thread = 0U;
    if (adapter.context.create_image_thread(adapter.context.userdata, second_image,
            second_routine, (void *)(uintptr_t)UINT32_C(0x2222), &second_thread) != URP_STATUS_OK
        || second_thread == 0U) return 13;
    void *cross_image_result = NULL;
    if (!expect(adapter.context.join_image_thread(adapter.context.userdata, image,
            second_thread, &cross_image_result) == URP_STATUS_INVALID_ARGUMENT,
            "foreign image thread handle was accepted")) return 14;
    if (adapter.context.join_image_thread(adapter.context.userdata, second_image,
            second_thread, &cross_image_result) != URP_STATUS_OK
        || cross_image_result != (void *)(uintptr_t)UINT32_C(0x2222)) return 15;
    uintptr_t self_raw = 0U;
    if (adapter.context.lookup_symbol(adapter.context.userdata, image,
            "urp_thread_self_join_worker", NULL, &self_raw) != URP_STATUS_OK) return 16;
    worker_fn self_routine = NULL;
    memcpy(&self_routine, &self_raw, sizeof(self_routine));
    struct self_join_probe_layout { const urp_host_context_v1 *host; urp_image_handle image; uint64_t thread; urp_status status; };
    struct self_join_probe_layout self_probe = { &adapter.context, image, 0U, URP_STATUS_OK };
    urp_image_thread_handle self_handle = 0U;
    if (adapter.context.create_image_thread(adapter.context.userdata, image, self_routine,
            &self_probe, &self_handle) != URP_STATUS_OK || self_handle == 0U) return 17;
    __atomic_store_n(&self_probe.thread, self_handle, __ATOMIC_RELEASE);
    void *self_result = NULL;
    if (adapter.context.join_image_thread(adapter.context.userdata, image,
            self_handle, &self_result) != URP_STATUS_OK
        || __atomic_load_n(&self_probe.status, __ATOMIC_ACQUIRE) != URP_STATUS_INVALID_ARGUMENT)
        return 18;
    urp_image_thread_handle handle = 0U;
    if (!expect(adapter.context.create_image_thread(adapter.context.userdata, image,
            NULL, NULL, &handle) == URP_STATUS_INVALID_ARGUMENT && handle == 0U,
            "null routine did not fail cleanly")) return 13;
    urp_host_adapter_test_fail_next_thread_create();
    handle = UINT64_MAX;
    if (!expect(adapter.context.create_image_thread(adapter.context.userdata, image,
            routine, NULL, &handle) == URP_STATUS_LOAD_FAILED && handle == 0U,
            "failed pthread_create published a worker handle")) return 14;
    const void *expected_result = (void *)(uintptr_t)UINT32_C(0x9876);
    if (adapter.context.create_image_thread(adapter.context.userdata, image, routine,
            (void *)expected_result, &handle) != URP_STATUS_OK || handle == 0U) return 15;
    foreign_call_state foreign = { &adapter, image, handle, routine, 0, 0, 0, 0U };
    pthread_t outsider;
    if (pthread_create(&outsider, NULL, foreign_owner_calls, &foreign) != 0
        || pthread_join(outsider, NULL) != 0) return 15;
    if (!expect(foreign.create_status == URP_STATUS_UNSUPPORTED && foreign.published == 0U
            && foreign.join_status == URP_STATUS_INVALID_ARGUMENT
            && foreign.release_status == URP_STATUS_INVALID_ARGUMENT,
            "non-owner callback did not fail without changing ownership")) return 16;
    void *result = (void *)(uintptr_t)1U;
    urp_host_adapter_test_fail_next_thread_join();
    if (!expect(adapter.context.join_image_thread(adapter.context.userdata, image, handle, &result)
            == URP_STATUS_LOAD_FAILED && result == NULL,
            "join failure did not preserve ownership and clear its result")) return 17;
    if (adapter.context.join_image_thread(adapter.context.userdata, image, handle, &result)
            != URP_STATUS_OK || result != expected_result) return 18;
    if (!expect(adapter.context.join_image_thread(adapter.context.userdata, image,
            handle, &result) == URP_STATUS_INVALID_ARGUMENT,
            "repeated join unexpectedly succeeded")) return 19;
    if (!expect(adapter.context.join_image_thread(adapter.context.userdata, image,
            handle + 1U, &result) == URP_STATUS_INVALID_ARGUMENT,
            "foreign thread handle unexpectedly joined")) return 20;
    urp_image_thread_handle release_thread = 0U;
    if (adapter.context.create_image_thread(adapter.context.userdata, second_image,
            second_routine, NULL, &release_thread) != URP_STATUS_OK || release_thread == 0U) return 21;
    urp_host_adapter_test_fail_next_thread_join();
    if (!expect(adapter.context.release_image(adapter.context.userdata, second_image)
            == URP_STATUS_LOAD_FAILED,
            "release join failure unloaded or forgot the live image")) return 22;
    if (adapter.context.release_image(adapter.context.userdata, second_image) != URP_STATUS_OK
        || adapter.context.release_image(adapter.context.userdata, image) != URP_STATUS_OK) return 23;
    handle = UINT64_MAX;
    urp_status after_release = adapter.context.create_image_thread(adapter.context.userdata,
        image, routine, NULL, &handle);
    if (!expect(after_release == URP_STATUS_INVALID_ARGUMENT && handle == 0U,
            "spawn after release published a worker")) return 15;
    void *dynamic_bytes = NULL;
    size_t dynamic_size = 0U;
    if (!read_bytes(argv[2], &dynamic_bytes, &dynamic_size)) return 24;
    size_t attempts_before = urp_host_adapter_memfd_create_attempts();
    urp_image_handle dynamic_image = UINT64_C(0xfeedface);
    urp_status dynamic_status = adapter.context.load_image(adapter.context.userdata,
        dynamic_bytes, dynamic_size, URP_LOAD_IMAGE_IMMUTABLE, &dynamic_image);
    free(dynamic_bytes);
    if (!expect(dynamic_status == URP_STATUS_UNSUPPORTED && dynamic_image == 0U
            && urp_host_adapter_memfd_create_attempts() == attempts_before,
            "dynamic TLS reached memfd creation or published an image")) return 25;
    puts("thread adapter ownership/join/order and dynamic-TLS negatives: PASS");
    return 0;
}
