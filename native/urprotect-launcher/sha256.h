#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct urp_sha256_context {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t block[64];
    size_t block_length;
} urp_sha256_context;

void urp_sha256_init(urp_sha256_context *context);
void urp_sha256_update(urp_sha256_context *context, const uint8_t *data, size_t length);
void urp_sha256_final(urp_sha256_context *context, uint8_t digest[32]);
