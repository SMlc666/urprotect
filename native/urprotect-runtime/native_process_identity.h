#ifndef URP_NATIVE_PROCESS_IDENTITY_H
#define URP_NATIVE_PROCESS_IDENTITY_H

#include <stddef.h>
#include <stdint.h>

/*
 * Capture evidence-only identity of the current native process's mapped
 * AArch64 runtime and helper executable. The retained carrier is relative to
 * the evidence root; no product ABI or image field is changed.
 */
int urp_native_process_identity_capture(
    const char *directory_path,
    const char *relative_directory,
    const char *role,
    const char *image_sha256,
    char *identity_relative_path,
    size_t identity_relative_path_capacity,
    char identity_sha256[65]);

#ifdef URP_NATIVE_PROCESS_IDENTITY_TEST
int urp_native_process_identity_test_verify_maps(
    const uint8_t *maps,
    size_t maps_size,
    const char *mapped_path,
    const uint8_t *elf_bytes,
    size_t elf_size,
    int require_executable_mapping);
#endif

#endif
