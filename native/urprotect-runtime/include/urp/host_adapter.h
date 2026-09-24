#ifndef URP_HOST_ADAPTER_H
#define URP_HOST_ADAPTER_H

#include "urp/host_context.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct urp_host_adapter_v1 {
    urp_host_context_v1 context;
} urp_host_adapter_v1;

/* Initialize the fd-backed host implementation used by native evidence tests. */
void urp_host_adapter_init(urp_host_adapter_v1 *adapter);

/* Return nonzero only when the adapter image fd carries every required seal. */
int urp_host_adapter_image_is_sealed(urp_image_handle handle);

#ifdef __cplusplus
}
#endif

#endif
