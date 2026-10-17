#ifndef URP_HOST_IMAGE_VALIDATION_H
#define URP_HOST_IMAGE_VALIDATION_H

#include <stddef.h>

#include "urp/host_context.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Validate an in-memory AArch64 ET_DYN image before loader handoff. This
 * preflight is intentionally independent from fd/dlopen ownership so every
 * failed validation returns before an image handle can be created.
 */
typedef struct urp_host_external_provider_facts {
    uint64_t table_virtual_address;
    uint8_t table_bytes[16];
} urp_host_external_provider_facts;

urp_status urp_host_image_validate(
    const void *bytes,
    size_t image_size,
    size_t *out_dependency_count);

/* Provider-specific validation remains separate from ordinary dependency policy. */
urp_status urp_host_image_validate_with_provider(
    const void *bytes,
    size_t image_size,
    const char *expected_provider_soname,
    size_t *out_dependency_count,
    int *out_uses_provider,
    uint64_t *out_provider_got_virtual_address);

/* Validate the one dependency-free, read-only signed-relative provider DSO. */
urp_status urp_host_external_provider_validate(
    const void *bytes,
    size_t image_size,
    const char *expected_soname,
    const char *expected_build_id_hex,
    urp_host_external_provider_facts *out_facts);

#if defined(URP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS)
void urp_host_image_validation_test_set_provider_work_limit(uint64_t limit);
uint64_t urp_host_image_validation_test_provider_candidate_work_used(void);
uint64_t urp_host_image_validation_test_provider_candidate_dynamic_entries(void);
uint64_t urp_host_image_validation_test_provider_candidate_range_work(void);
uint64_t urp_host_image_validation_test_provider_candidate_needed_string_bytes(void);
uint64_t urp_host_image_validation_test_consumer_rela_validation_count(void);
uint64_t urp_host_image_validation_test_symbol_version_validation_count(void);
uint64_t urp_host_image_validation_test_provider_parse_work_used(void);
uint64_t urp_host_image_validation_test_provider_parse_count(void);
#endif

#ifdef __cplusplus
}
#endif

#endif
