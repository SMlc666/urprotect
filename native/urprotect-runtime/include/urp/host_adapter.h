#ifndef URP_HOST_ADAPTER_H
#define URP_HOST_ADAPTER_H

#include "urp/host_context.h"

#ifdef __cplusplus
extern "C" {
#endif

#define URP_HOST_PROVIDER_PATH_CAPACITY 4096U
#define URP_HOST_PROVIDER_SONAME_CAPACITY 128U
#define URP_HOST_PROVIDER_BUILD_ID_HEX_CAPACITY 41U
#define URP_HOST_PROVIDER_SHA256_HEX_CAPACITY 65U
#define URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME "liburprotect-jump-table-provider.so.1"
#define URP_HOST_EXTERNAL_TABLE_SYMBOL "urp_external_jump_table"

typedef struct urp_host_provider_config_v1 {
    const char *path;
    const char *expected_soname;
    const char *expected_build_id_hex;
    const char *expected_sha256_hex;
} urp_host_provider_config_v1;

typedef struct urp_host_adapter_v1 {
    urp_host_context_v1 context;
    uint32_t provider_configured;
    char provider_path[URP_HOST_PROVIDER_PATH_CAPACITY];
    char provider_soname[URP_HOST_PROVIDER_SONAME_CAPACITY];
    char provider_build_id_hex[URP_HOST_PROVIDER_BUILD_ID_HEX_CAPACITY];
    char provider_sha256_hex[URP_HOST_PROVIDER_SHA256_HEX_CAPACITY];
} urp_host_adapter_v1;

/* Initialize the fd-backed host implementation used by native evidence tests. */
void urp_host_adapter_init(urp_host_adapter_v1 *adapter);

/* Configure one host-trusted external-table provider; values are copied. */
urp_status urp_host_adapter_init_with_provider(
    urp_host_adapter_v1 *adapter,
    const urp_host_provider_config_v1 *provider);

/* Return nonzero only when the adapter image fd carries every required seal. */
int urp_host_adapter_image_is_sealed(urp_image_handle handle);

/* Evidence-test probe: number of memfd_create attempts in this process. */
#if defined(URP_HOST_ADAPTER_TEST_DIAGNOSTICS)
size_t urp_host_adapter_memfd_create_attempts(void);
size_t urp_host_adapter_loader_attempts(void);
void urp_host_adapter_test_fail_next_thread_create(void);
void urp_host_adapter_test_fail_next_thread_join(void);
#endif

#ifdef __cplusplus
}
#endif

#endif
