#define _GNU_SOURCE
#include "host_context_cfi_exception_bridge.h"
#include "urp/host_adapter.h"

#include <dlfcn.h>
#include <execinfo.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define ELF_HEADER_SIZE 64U
#define PROGRAM_HEADER_SIZE 56U
#define SECTION_HEADER_SIZE 64U
#define SHT_SYMTAB 2U
#define SHT_STRTAB 3U
#define PT_LOAD 1U
#define PF_X 1U
#define STT_FUNC 2U
#define TARGET_SYMBOL "urp_transform_target"
#define CALLEE_SAVED_X19 ((uintptr_t)UINT64_C(0x1122334455667788))
#define CALLEE_SAVED_X20 ((uintptr_t)UINT64_C(0x8877665544332211))

typedef urp_cfi_target_fn cfi_target_fn;

typedef enum cfi_behavior_mode {
    CfiNormal,
    CfiSignal,
    CfiLongjmp,
    CfiCppException,
    CfiCancellation,
} cfi_behavior_mode;

typedef struct cfi_state {
    uintptr_t image_load_bias;
    uintptr_t loaded_entry_address;
    uintptr_t loaded_entry_virtual_address;
    uintptr_t target_address;
    uintptr_t target_end;
    uint64_t mapped_target_virtual_address;
    uint64_t mapped_target_size;
    uintptr_t callback_return_pc;
    uintptr_t target_frame_pc;
    uintptr_t cpp_throw_site_return_pc;
    uintptr_t cpp_throw_site_target_frame_pc;
    size_t frame_count;
    size_t signal_frame_count;
    int target_frame_observed;
    int signal_frame_observed;
    int frame_pointer_aligned;
    int return_address_in_target;
    int registers_preserved;
    int signal_seen;
    int longjmp_boundary;
    int cpp_throw_site_target_frame_observed;
    int cpp_host_callback_returned;
    unsigned cpp_host_callback_entered;
    uint64_t cpp_throw_token;
    int cancellation_boundary;
    int cancellation_cleanup;
    int cancellation_target_returned;
    int32_t cancellation_target_status;
    unsigned diagnostic_calls;
    cfi_behavior_mode mode;
    jmp_buf longjmp_environment;
    int longjmp_environment_active;
} cfi_state;

typedef struct cfi_thread_call {
    cfi_target_fn target;
    const urp_host_context_v1 *host;
    const urp_launch_args_v1 *args;
    cfi_state *state;
} cfi_thread_call;

static cfi_state *active_state;

static uint16_t read_u16(const uint8_t *bytes)
{
    return (uint16_t)bytes[0] | (uint16_t)((uint16_t)bytes[1] << 8U);
}

static uint32_t read_u32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0]
        | ((uint32_t)bytes[1] << 8U)
        | ((uint32_t)bytes[2] << 16U)
        | ((uint32_t)bytes[3] << 24U);
}

static uint64_t read_u64(const uint8_t *bytes)
{
    uint64_t value = 0U;
    for (unsigned index = 0U; index < 8U; ++index) {
        value |= (uint64_t)bytes[index] << (index * 8U);
    }
    return value;
}

static int range_in_file(size_t image_size, uint64_t offset, uint64_t size)
{
    return offset <= (uint64_t)image_size
        && size <= (uint64_t)image_size - offset;
}

static int range_in_image(
    const uint8_t *image,
    size_t image_size,
    uint64_t offset,
    uint64_t size,
    const uint8_t **bytes_out)
{
    if (!range_in_file(image_size, offset, size)) {
        return 0;
    }
    *bytes_out = image + (size_t)offset;
    return 1;
}

static int find_section(
    const uint8_t *image,
    size_t image_size,
    uint64_t section_table_offset,
    uint16_t section_count,
    uint16_t index,
    const uint8_t **section_out)
{
    uint64_t offset = section_table_offset + (uint64_t)index * SECTION_HEADER_SIZE;
    if (index >= section_count
        || offset < section_table_offset
        || !range_in_file(image_size, offset, SECTION_HEADER_SIZE)) {
        return 0;
    }
    *section_out = image + (size_t)offset;
    return 1;
}

static int find_target_symbol(
    const uint8_t *image,
    size_t image_size,
    const char *name,
    uint64_t *value_out,
    uint64_t *size_out)
{
    if (image_size < ELF_HEADER_SIZE
        || read_u16(image + 58U) != SECTION_HEADER_SIZE) {
        return 0;
    }

    uint64_t section_table_offset = read_u64(image + 40U);
    uint16_t section_count = read_u16(image + 60U);
    for (uint16_t section_index = 0U; section_index < section_count; ++section_index) {
        const uint8_t *section;
        if (!find_section(
                image,
                image_size,
                section_table_offset,
                section_count,
                section_index,
                &section)
            || read_u32(section + 4U) != SHT_SYMTAB
            || read_u64(section + 56U) != 24U) {
            continue;
        }

        uint32_t string_section_index = read_u32(section + 40U);
        const uint8_t *string_section;
        if (!find_section(
                image,
                image_size,
                section_table_offset,
                section_count,
                (uint16_t)string_section_index,
                &string_section)) {
            return 0;
        }

        const uint8_t *strings;
        uint64_t string_size = read_u64(string_section + 32U);
        if (read_u32(string_section + 4U) != SHT_STRTAB
            || !range_in_image(
                image,
                image_size,
                read_u64(string_section + 24U),
                string_size,
                &strings)) {
            return 0;
        }

        uint64_t symbol_count = read_u64(section + 32U) / 24U;
        const uint8_t *symbol_bytes;
        if (!range_in_image(
                image,
                image_size,
                read_u64(section + 24U),
                read_u64(section + 32U),
                &symbol_bytes)) {
            return 0;
        }

        for (uint64_t symbol_index = 0U; symbol_index < symbol_count; ++symbol_index) {
            const uint8_t *symbol = symbol_bytes + (size_t)(symbol_index * 24U);
            uint32_t name_offset = read_u32(symbol);
            if (name_offset >= string_size
                || (symbol[4U] & 0x0fU) != STT_FUNC) {
                continue;
            }

            size_t remaining = (size_t)string_size - name_offset;
            const char *symbol_name = (const char *)(strings + name_offset);
            if (memchr(symbol_name, 0, remaining) == NULL
                || strcmp(symbol_name, name) != 0) {
                continue;
            }

            *value_out = read_u64(symbol + 8U);
            *size_out = read_u64(symbol + 16U);
            return *value_out != 0U && *size_out != 0U;
        }
    }
    return 0;
}

static int count_executable_loads(const uint8_t *image, size_t image_size)
{
    uint64_t program_header_offset = read_u64(image + 32U);
    uint16_t entry_size = read_u16(image + 54U);
    uint16_t count = read_u16(image + 56U);
    int executable_count = 0;

    if (entry_size != PROGRAM_HEADER_SIZE
        || count == 0U
        || count > 4096U
        || !range_in_file(
            image_size,
            program_header_offset,
            (uint64_t)count * entry_size)) {
        return 0;
    }

    for (uint16_t index = 0U; index < count; ++index) {
        const uint8_t *header = image
            + (size_t)(program_header_offset + (uint64_t)index * entry_size);
        if (read_u32(header) == PT_LOAD && (read_u32(header + 4U) & PF_X) != 0U) {
            ++executable_count;
        }
    }
    return executable_count;
}

static void capture_backtrace(cfi_state *state, int signal_context)
{
    void *frames[64];
    int count = backtrace(frames, (int)(sizeof(frames) / sizeof(frames[0])));
    if (count < 0) {
        return;
    }

    if (signal_context != 0) {
        state->signal_frame_count = (size_t)count;
    } else {
        state->frame_count = (size_t)count;
    }

    for (int index = 0; index < count; ++index) {
        uintptr_t address = (uintptr_t)frames[index];
        if (state->target_end > state->target_address
            && address >= state->target_address
            && address < state->target_end) {
            if (state->mode == CfiNormal && state->target_frame_pc == 0U) {
                state->target_frame_pc = address;
            }
            if (state->mode == CfiCppException
                && state->cpp_throw_site_target_frame_pc == 0U) {
                state->cpp_throw_site_target_frame_pc = address;
            }
            if (signal_context != 0) {
                state->signal_frame_observed = 1;
            } else {
                state->target_frame_observed = 1;
            }
        }
    }
}

static void cfi_signal_handler(int signal_number)
{
    (void)signal_number;
    if (active_state != NULL) {
        active_state->signal_seen = 1;
        capture_backtrace(active_state, 1);
    }
}

static urp_status capture_diagnostic(void *userdata, uint32_t code, const char *message)
{
    (void)userdata;
    (void)code;
    (void)message;
    if (active_state == NULL) {
        return URP_STATUS_INVALID_ARGUMENT;
    }

    active_state->diagnostic_calls++;
    uintptr_t frame_pointer = (uintptr_t)__builtin_frame_address(0);
    uintptr_t return_address = (uintptr_t)__builtin_return_address(0);
    active_state->callback_return_pc = return_address;
    active_state->frame_pointer_aligned = frame_pointer != 0U
        && (frame_pointer & 0x0fU) == 0U;
    active_state->return_address_in_target = return_address >= active_state->target_address
        && return_address < active_state->target_end;
    capture_backtrace(active_state, 0);

    if (active_state->mode == CfiSignal) {
        (void)raise(SIGUSR1);
    } else if (active_state->mode == CfiLongjmp
        && active_state->longjmp_environment_active != 0) {
        longjmp(active_state->longjmp_environment, 1);
    } else if (active_state->mode == CfiCppException) {
        active_state->cpp_host_callback_entered++;
        active_state->cpp_throw_site_return_pc = return_address;
        active_state->cpp_throw_site_target_frame_observed =
            active_state->return_address_in_target != 0
            && active_state->target_frame_observed != 0;
        urp_cfi_cpp_throw_from_host_callback(active_state->cpp_throw_token);
        active_state->cpp_host_callback_returned = 1;
    } else if (active_state->mode == CfiCancellation) {
        (void)pthread_cancel(pthread_self());
        pthread_testcancel();
    }
    return URP_STATUS_OK;
}

static void cancellation_cleanup(void *opaque)
{
    cfi_state *state = (cfi_state *)opaque;
    state->cancellation_cleanup = 1;
}

static void *cancellation_thread(void *opaque)
{
    cfi_thread_call *call = (cfi_thread_call *)opaque;
    void *result = NULL;
    pthread_cleanup_push(cancellation_cleanup, call->state);
    call->state->cancellation_target_status = call->target(call->host, call->args);
    call->state->cancellation_target_returned = 1;
    result = (void *)(intptr_t)call->state->cancellation_target_status;
    pthread_cleanup_pop(1);
    return result;
}

static int run_longjmp_boundary(
    cfi_target_fn target,
    const urp_host_context_v1 *host,
    const urp_launch_args_v1 *args,
    cfi_state *state)
{
    state->mode = CfiLongjmp;
    state->longjmp_boundary = 0;
    state->longjmp_environment_active = 0;
    if (setjmp(state->longjmp_environment) == 0) {
        state->longjmp_environment_active = 1;
        (void)target(host, args);
        state->longjmp_environment_active = 0;
        return 0;
    }
    state->longjmp_boundary = 1;
    state->longjmp_environment_active = 0;
    return 1;
}

static int read_image(const char *path, uint8_t **bytes_out, size_t *size_out)
{
    FILE *stream = fopen(path, "rb");
    long length;
    uint8_t *bytes;

    if (stream == NULL || fseek(stream, 0, SEEK_END) != 0) {
        if (stream != NULL) {
            (void)fclose(stream);
        }
        return 0;
    }
    length = ftell(stream);
    if (length <= 0 || fseek(stream, 0, SEEK_SET) != 0) {
        (void)fclose(stream);
        return 0;
    }
    bytes = (uint8_t *)malloc((size_t)length);
    if (bytes == NULL
        || fread(bytes, 1U, (size_t)length, stream) != (size_t)length) {
        free(bytes);
        (void)fclose(stream);
        return 0;
    }
    (void)fclose(stream);
    *bytes_out = bytes;
    *size_out = (size_t)length;
    return 1;
}

int main(int argc, char **argv)
{
    uint8_t *image = NULL;
    size_t image_size = 0U;
    urp_host_adapter_v1 adapter;
    urp_image_handle handle = 0U;
    uintptr_t entry_address = 0U;
    uintptr_t target_offset = 0U;
    uint64_t target_size = 0U;
    uint64_t cpp_throw_token = URP_CFI_CPP_TEST_TOKEN;
    cfi_target_fn target;
    const char *target_argv[] = { "cfi-runtime-test", NULL };
    urp_launch_args_v1 args;
    cfi_state state = {0};
    cfi_state cpp_exception_state;
    urp_cfi_cpp_exception_result cpp_exception_result = {0};
    struct sigaction signal_action = {0};
    int32_t target_status = -1;
    int cpp_exception_boundary_status = -1;
    int expected_transformed = 0;
    int has_target_override = 0;
    uint64_t target_virtual_address = 0U;
    uint64_t target_virtual_size = 0U;

    for (int index = 2; index < argc; ++index) {
        if (strcmp(argv[index], "--expect-transformed") == 0) {
            expected_transformed = 1;
        } else if (strcmp(argv[index], "--target-vaddr") == 0 && index + 1 < argc) {
            char *end = NULL;
            errno = 0;
            target_virtual_address = strtoull(argv[++index], &end, 0);
            if (errno != 0 || end == argv[index] || *end != '\0') return 2;
            has_target_override = 1;
        } else if (strcmp(argv[index], "--target-size") == 0 && index + 1 < argc) {
            char *end = NULL;
            errno = 0;
            target_virtual_size = strtoull(argv[++index], &end, 0);
            if (errno != 0 || end == argv[index] || *end != '\0') return 2;
        } else if (strcmp(argv[index], "--cpp-token") == 0 && index + 1 < argc) {
            char *end = NULL;
            errno = 0;
            cpp_throw_token = strtoull(argv[++index], &end, 0);
            if (errno != 0 || end == argv[index] || *end != '\0') return 2;
        } else {
            return 2;
        }
    }
    if (argc < 2 || (has_target_override && target_virtual_size == 0U)) return 2;
    if (!read_image(argv[1], &image, &image_size)) {
        return 2;
    }
    if (!has_target_override
        && !find_target_symbol(image, image_size, TARGET_SYMBOL, &target_offset, &target_size)) {
        free(image);
        return 3;
    }
    if (has_target_override) {
        target_offset = target_virtual_address;
        target_size = target_virtual_size;
    }

    urp_host_adapter_init(&adapter);
    adapter.context.emit_diagnostic = capture_diagnostic;
    active_state = &state;
    signal_action.sa_handler = cfi_signal_handler;
    sigemptyset(&signal_action.sa_mask);
    signal_action.sa_flags = 0;
    (void)sigaction(SIGUSR1, &signal_action, NULL);

    if (adapter.context.load_image(
            adapter.context.userdata,
            image,
            image_size,
            URP_LOAD_IMAGE_IMMUTABLE,
            &handle) != URP_STATUS_OK
        || handle == 0U
        || adapter.context.lookup_symbol(
            adapter.context.userdata,
            handle,
            "urp_entry",
            NULL,
            &entry_address) != URP_STATUS_OK) {
        free(image);
        return 3;
    }

    Dl_info info;
    if (dladdr((void *)entry_address, &info) == 0 || info.dli_fbase == NULL
        || target_offset > UINTPTR_MAX - (uintptr_t)info.dli_fbase
        || target_size > UINTPTR_MAX - ((uintptr_t)info.dli_fbase + (uintptr_t)target_offset)) {
        (void)adapter.context.release_image(adapter.context.userdata, handle);
        free(image);
        return 3;
    }
    state.image_load_bias = (uintptr_t)info.dli_fbase;
    state.loaded_entry_address = entry_address;
    if (entry_address < state.image_load_bias) {
        (void)adapter.context.release_image(adapter.context.userdata, handle);
        free(image);
        return 3;
    }
    state.loaded_entry_virtual_address = entry_address - state.image_load_bias;
    state.mapped_target_virtual_address = (uint64_t)target_offset;
    state.mapped_target_size = target_size;
    state.target_address = state.image_load_bias + (uintptr_t)target_offset;
    state.target_end = state.target_address + (uintptr_t)target_size;
    if (state.target_end <= state.target_address) {
        (void)adapter.context.release_image(adapter.context.userdata, handle);
        free(image);
        return 3;
    }

    /* Call the public entry stub, but verify unwinding against the actual
     * protected function's mapped FDE range. Flattening relocates the function
     * to a new executable segment while urp_entry remains an ABI-visible stub.
     * Those are distinct addresses and must not be conflated in this oracle. */
    memcpy(&target, &entry_address, sizeof(target));
    args.abi_version = URP_HOST_ABI_VERSION;
    args.struct_size = URP_LAUNCH_ARGS_CURRENT_SIZE;
    args.argc = 1U;
    args.argv = target_argv;
    args.envp = NULL;
    args.image = handle;

    state.mode = CfiNormal;
    uintptr_t observed_x19 = 0U;
    uintptr_t observed_x20 = 0U;
    target_status = urp_cfi_invoke_with_registers(
        target,
        &adapter.context,
        &args,
        &observed_x19,
        &observed_x20);
    state.registers_preserved = observed_x19 == CALLEE_SAVED_X19
        && observed_x20 == CALLEE_SAVED_X20;

    cfi_state signal_state = state;
    signal_state.mode = CfiSignal;
    signal_state.signal_seen = 0;
    signal_state.signal_frame_observed = 0;
    signal_state.diagnostic_calls = 0;
    active_state = &signal_state;
    int32_t signal_status = target(&adapter.context, &args);

    cfi_state longjmp_state = state;
    longjmp_state.diagnostic_calls = 0;
    active_state = &longjmp_state;
    (void)run_longjmp_boundary(target, &adapter.context, &args, &longjmp_state);

    cpp_exception_state = state;
    cpp_exception_state.mode = CfiCppException;
    cpp_exception_state.diagnostic_calls = 0;
    cpp_exception_state.target_frame_observed = 0;
    cpp_exception_state.frame_count = 0U;
    cpp_exception_state.frame_pointer_aligned = 0;
    cpp_exception_state.return_address_in_target = 0;
    cpp_exception_state.cpp_throw_site_target_frame_observed = 0;
    cpp_exception_state.cpp_host_callback_returned = 0;
    cpp_exception_state.cpp_host_callback_entered = 0U;
    cpp_exception_state.cpp_throw_token = cpp_throw_token;
    active_state = &cpp_exception_state;
    uintptr_t cpp_observed_x19 = 0U;
    uintptr_t cpp_observed_x20 = 0U;
    cpp_exception_boundary_status = urp_cfi_run_cpp_exception_boundary(
        target,
        &adapter.context,
        &args,
        &cpp_observed_x19,
        &cpp_observed_x20,
        &cpp_exception_result);

    cfi_state cancellation_state = state;
    cancellation_state.mode = CfiCancellation;
    cancellation_state.cancellation_cleanup = 0;
    cancellation_state.cancellation_target_returned = 0;
    cancellation_state.diagnostic_calls = 0;
    active_state = &cancellation_state;
    cfi_thread_call call = { target, &adapter.context, &args, &cancellation_state };
    pthread_t cancellation_thread_handle;
    int thread_create_status = pthread_create(
        &cancellation_thread_handle,
        NULL,
        cancellation_thread,
        &call);
    int thread_join_status = thread_create_status == 0
        ? pthread_join(cancellation_thread_handle, NULL)
        : -1;
    cancellation_state.cancellation_boundary = thread_create_status == 0
        && thread_join_status == 0
        && cancellation_state.cancellation_cleanup != 0
        && cancellation_state.cancellation_target_returned == 0;

    active_state = &state;
    urp_status release_status = adapter.context.release_image(
        adapter.context.userdata,
        handle);
    active_state = NULL;

    int image_is_transformed = count_executable_loads(image, image_size) > 1;
    state.target_frame_observed = state.target_frame_observed != 0;
    int transformed_frame_observed = image_is_transformed
        && state.target_frame_observed;
    printf(
        "schemaVersion=2 targetStatus=%d signalStatus=%d diagnosticCalls=%u "
        "frameCount=%zu signalFrameCount=%zu transformedImage=%d "
        "targetFrameObserved=%d transformedFrameObserved=%d framePointerAligned=%d "
        "returnAddressInTarget=%d registersPreserved=%d signalBoundary=%d "
        "signalFrameObserved=%d longjmpBoundary=%d cancellationBoundary=%d "
        "cppBoundaryStatus=%d cppRegisterCallAttempted=%u cppRegisterCallReturned=%u "
        "cppTargetNormalReturned=%u cppCaughtSpecificType=%u cppCaughtToken=0x%llx "
        "cppRaiiCleanupCount=%u cppHostCallbackEntered=%u cppHostCallbackReturned=%d "
        "cppThrowSiteTargetFrameObserved=%d cppThrowSiteFrameCount=%zu "
        "cppThrowSiteReturnAddressInTarget=%d cppThrowSiteReturnPc=0x%lx "
        "cppThrowSiteTargetFramePc=0x%lx releaseStatus=%d "
        "imageLoadBias=0x%lx loadedEntryAddress=0x%lx loadedEntryVaddr=0x%lx "
        "mappedTargetVaddr=0x%llx mappedTargetSize=%llu callbackReturnPc=0x%lx "
        "targetFramePc=0x%lx targetRangeStart=0x%lx targetRangeEnd=0x%lx "
        "targetInvocationMode=%s targetSymbolSize=%llu\n",
        target_status,
        signal_status,
        state.diagnostic_calls,
        state.frame_count,
        signal_state.signal_frame_count,
        image_is_transformed,
        state.target_frame_observed,
        transformed_frame_observed,
        state.frame_pointer_aligned,
        state.return_address_in_target,
        state.registers_preserved,
        signal_state.signal_seen != 0 && signal_status == 42,
        signal_state.signal_frame_observed,
        longjmp_state.longjmp_boundary,
        cancellation_state.cancellation_boundary,
        cpp_exception_boundary_status,
        cpp_exception_result.register_call_attempted,
        cpp_exception_result.register_call_returned,
        cpp_exception_result.normal_target_returned,
        cpp_exception_result.caught_specific_type,
        (unsigned long long)cpp_exception_result.caught_token,
        cpp_exception_result.cleanup_count,
        cpp_exception_state.cpp_host_callback_entered,
        cpp_exception_state.cpp_host_callback_returned,
        cpp_exception_state.cpp_throw_site_target_frame_observed,
        cpp_exception_state.frame_count,
        cpp_exception_state.return_address_in_target,
        (unsigned long)cpp_exception_state.cpp_throw_site_return_pc,
        (unsigned long)cpp_exception_state.cpp_throw_site_target_frame_pc,
        release_status,
        (unsigned long)state.image_load_bias,
        (unsigned long)state.loaded_entry_address,
        (unsigned long)state.loaded_entry_virtual_address,
        (unsigned long long)state.mapped_target_virtual_address,
        (unsigned long long)state.mapped_target_size,
        (unsigned long)state.callback_return_pc,
        (unsigned long)state.target_frame_pc,
        (unsigned long)state.target_address,
        (unsigned long)state.target_end,
        has_target_override != 0 ? "address-map" : "direct-symbol",
        (unsigned long long)target_size);

    free(image);

    if (target_status != 42
        || signal_status != 42
        || state.diagnostic_calls != 1U
        || state.frame_count < 2U
        || state.target_frame_observed == 0
        || state.frame_pointer_aligned == 0
        || state.return_address_in_target == 0
        || state.registers_preserved == 0
        || signal_state.signal_seen == 0
        || signal_state.signal_frame_observed == 0
        || longjmp_state.longjmp_boundary == 0
        || cpp_exception_boundary_status != 1
        || cpp_exception_result.register_call_attempted != 1U
        || cpp_exception_result.register_call_returned != 0U
        || cpp_exception_result.normal_target_returned != 0U
        || cpp_exception_result.caught_specific_type != 1U
        || cpp_exception_result.caught_token != URP_CFI_CPP_TEST_TOKEN
        || cpp_exception_result.cleanup_count != 1U
        || cpp_exception_state.cpp_host_callback_entered != 1U
        || cpp_exception_state.cpp_host_callback_returned != 0
        || cpp_exception_state.cpp_throw_site_target_frame_observed == 0
        || cpp_exception_state.target_frame_observed == 0
        || cpp_exception_state.return_address_in_target == 0
        || cancellation_state.cancellation_boundary == 0
        || release_status != URP_STATUS_OK
        || (expected_transformed
            && (!image_is_transformed || !transformed_frame_observed))) {
        return 4;
    }
    return 0;
}
