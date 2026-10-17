#ifndef URP_HOST_CONTEXT_CFI_EXCEPTION_BRIDGE_H
#define URP_HOST_CONTEXT_CFI_EXCEPTION_BRIDGE_H

#include <stdint.h>
#include "urp/host_context.h"

#ifdef __cplusplus
extern "C" {
#endif

#define URP_CFI_CPP_TEST_TOKEN UINT64_C(0x4346495f45584331)

typedef int32_t (*urp_cfi_target_fn)(
    const urp_host_context_v1 *host,
    const urp_launch_args_v1 *args);

typedef struct urp_cfi_cpp_exception_result {
    int32_t target_status;
    uint64_t caught_token;
    uint32_t register_call_attempted;
    uint32_t register_call_returned;
    uint32_t normal_target_returned;
    uint32_t caught_specific_type;
    uint32_t cleanup_count;
} urp_cfi_cpp_exception_result;

int32_t urp_cfi_invoke_with_registers(
    urp_cfi_target_fn target,
    const urp_host_context_v1 *host,
    const urp_launch_args_v1 *args,
    uintptr_t *observed_x19,
    uintptr_t *observed_x20);

void urp_cfi_cpp_throw_from_host_callback(uint64_t token);
int urp_cfi_run_cpp_exception_boundary(
    urp_cfi_target_fn target,
    const urp_host_context_v1 *host,
    const urp_launch_args_v1 *args,
    uintptr_t *observed_x19,
    uintptr_t *observed_x20,
    urp_cfi_cpp_exception_result *result);

#ifdef __cplusplus
}
#endif

#endif
