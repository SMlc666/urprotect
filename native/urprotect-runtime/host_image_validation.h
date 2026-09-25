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
urp_status urp_host_image_validate(const void *bytes, size_t image_size);

#ifdef __cplusplus
}
#endif

#endif
