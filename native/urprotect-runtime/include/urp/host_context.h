#ifndef URP_HOST_CONTEXT_H
#define URP_HOST_CONTEXT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define URP_HOST_ABI_VERSION UINT32_C(1)
#define URP_HOST_CONTEXT_MIN_SIZE UINT32_C(56)
#define URP_LAUNCH_ARGS_MIN_SIZE UINT32_C(32)
#define URP_HOST_ENTRY_SYMBOL "urp_entry"

#define URP_HOST_CAP_LOAD_IMAGE (UINT64_C(1) << 0)
#define URP_HOST_CAP_LOOKUP_SYMBOL (UINT64_C(1) << 1)
#define URP_HOST_CAP_EMIT_DIAGNOSTIC (UINT64_C(1) << 2)
#define URP_HOST_CAP_RELEASE_IMAGE (UINT64_C(1) << 3)

#define URP_LOAD_IMAGE_IMMUTABLE UINT32_C(1)

#define URP_STATUS_OK INT32_C(0)
#define URP_STATUS_INVALID_ARGUMENT INT32_C(-1)
#define URP_STATUS_UNSUPPORTED INT32_C(-2)
#define URP_STATUS_LOAD_FAILED INT32_C(-3)
#define URP_STATUS_SYMBOL_NOT_FOUND INT32_C(-4)
#define URP_STATUS_FRAME_INVALID INT32_C(-5)
#define URP_STATUS_INTEGRITY_FAILURE INT32_C(-6)
#define URP_STATUS_HOST_INVALID INT32_C(-7)

typedef int32_t urp_status;
typedef uint64_t urp_image_handle;

/* The host consumes bytes before load_image returns; the handle owns the image until release. */
typedef urp_status (*urp_load_image_fn)(
    void *userdata,
    const void *bytes,
    size_t size,
    uint32_t flags,
    urp_image_handle *out_handle);

typedef urp_status (*urp_lookup_symbol_fn)(
    void *userdata,
    urp_image_handle image,
    const char *name,
    const char *version,
    uintptr_t *out_address);

typedef urp_status (*urp_release_image_fn)(
    void *userdata,
    urp_image_handle image);

typedef urp_status (*urp_emit_diagnostic_fn)(
    void *userdata,
    uint32_t code,
    const char *message);

typedef struct urp_host_context_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint64_t capabilities;
    void *userdata;
    urp_load_image_fn load_image;
    urp_lookup_symbol_fn lookup_symbol;
    urp_release_image_fn release_image;
    urp_emit_diagnostic_fn emit_diagnostic;
} urp_host_context_v1;

typedef struct urp_launch_args_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t argc;
    const char *const *argv;
    const char *const *envp;
} urp_launch_args_v1;

typedef int32_t (*urp_entry_fn)(
    const urp_host_context_v1 *host,
    const urp_launch_args_v1 *args);

#ifdef __cplusplus
}
#endif

#endif
