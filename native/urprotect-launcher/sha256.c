#include "sha256.h"

#include <string.h>

static const uint32_t round_constants[64] = {
    0x428A2F98U, 0x71374491U, 0xB5C0FBCFU, 0xE9B5DBA5U,
    0x3956C25BU, 0x59F111F1U, 0x923F82A4U, 0xAB1C5ED5U,
    0xD807AA98U, 0x12835B01U, 0x243185BEU, 0x550C7DC3U,
    0x72BE5D74U, 0x80DEB1FEU, 0x9BDC06A7U, 0xC19BF174U,
    0xE49B69C1U, 0xEFBE4786U, 0x0FC19DC6U, 0x240CA1CCU,
    0x2DE92C6FU, 0x4A7484AAU, 0x5CB0A9DCU, 0x76F988DAU,
    0x983E5152U, 0xA831C66DU, 0xB00327C8U, 0xBF597FC7U,
    0xC6E00BF3U, 0xD5A79147U, 0x06CA6351U, 0x14292967U,
    0x27B70A85U, 0x2E1B2138U, 0x4D2C6DFCU, 0x53380D13U,
    0x650A7354U, 0x766A0ABBU, 0x81C2C92EU, 0x92722C85U,
    0xA2BFE8A1U, 0xA81A664BU, 0xC24B8B70U, 0xC76C51A3U,
    0xD192E819U, 0xD6990624U, 0xF40E3585U, 0x106AA070U,
    0x19A4C116U, 0x1E376C08U, 0x2748774CU, 0x34B0BCB5U,
    0x391C0CB3U, 0x4ED8AA4AU, 0x5B9CCA4FU, 0x682E6FF3U,
    0x748F82EEU, 0x78A5636FU, 0x84C87814U, 0x8CC70208U,
    0x90BEFFFAU, 0xA4506CEBU, 0xBEF9A3F7U, 0xC67178F2U,
};

static uint32_t rotate_right(uint32_t value, uint32_t amount)
{
    return (value >> amount) | (value << (32U - amount));
}

static uint32_t read_big_endian(const uint8_t *data)
{
    return ((uint32_t)data[0] << 24U)
        | ((uint32_t)data[1] << 16U)
        | ((uint32_t)data[2] << 8U)
        | (uint32_t)data[3];
}

static void write_big_endian(uint8_t *data, uint32_t value)
{
    data[0] = (uint8_t)(value >> 24U);
    data[1] = (uint8_t)(value >> 16U);
    data[2] = (uint8_t)(value >> 8U);
    data[3] = (uint8_t)value;
}

static void transform(urp_sha256_context *context, const uint8_t block[64])
{
    uint32_t words[64];
    for (size_t index = 0; index < 16; ++index) {
        words[index] = read_big_endian(block + (index * 4U));
    }
    for (size_t index = 16; index < 64; ++index) {
        uint32_t value = words[index - 15U];
        uint32_t sigma0 = rotate_right(value, 7U) ^ rotate_right(value, 18U) ^ (value >> 3U);
        value = words[index - 2U];
        uint32_t sigma1 = rotate_right(value, 17U) ^ rotate_right(value, 19U) ^ (value >> 10U);
        words[index] = words[index - 16U] + sigma0 + words[index - 7U] + sigma1;
    }

    uint32_t a = context->state[0];
    uint32_t b = context->state[1];
    uint32_t c = context->state[2];
    uint32_t d = context->state[3];
    uint32_t e = context->state[4];
    uint32_t f = context->state[5];
    uint32_t g = context->state[6];
    uint32_t h = context->state[7];
    for (size_t index = 0; index < 64; ++index) {
        uint32_t sigma1 = rotate_right(e, 6U) ^ rotate_right(e, 11U) ^ rotate_right(e, 25U);
        uint32_t choose = (e & f) ^ ((~e) & g);
        uint32_t temporary1 = h + sigma1 + choose + round_constants[index] + words[index];
        uint32_t sigma0 = rotate_right(a, 2U) ^ rotate_right(a, 13U) ^ rotate_right(a, 22U);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temporary2 = sigma0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + temporary1;
        d = c;
        c = b;
        b = a;
        a = temporary1 + temporary2;
    }

    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
    context->state[4] += e;
    context->state[5] += f;
    context->state[6] += g;
    context->state[7] += h;
}

void urp_sha256_init(urp_sha256_context *context)
{
    context->state[0] = 0x6A09E667U;
    context->state[1] = 0xBB67AE85U;
    context->state[2] = 0x3C6EF372U;
    context->state[3] = 0xA54FF53AU;
    context->state[4] = 0x510E527FU;
    context->state[5] = 0x9B05688CU;
    context->state[6] = 0x1F83D9ABU;
    context->state[7] = 0x5BE0CD19U;
    context->bit_count = 0;
    context->block_length = 0;
}

void urp_sha256_update(urp_sha256_context *context, const uint8_t *data, size_t length)
{
    context->bit_count += (uint64_t)length * 8U;
    while (length > 0) {
        size_t available = 64U - context->block_length;
        size_t copied = length < available ? length : available;
        memcpy(context->block + context->block_length, data, copied);
        context->block_length += copied;
        data += copied;
        length -= copied;
        if (context->block_length == 64U) {
            transform(context, context->block);
            context->block_length = 0;
        }
    }
}

void urp_sha256_final(urp_sha256_context *context, uint8_t digest[32])
{
    size_t index = context->block_length;
    context->block[index++] = 0x80U;
    if (index > 56U) {
        memset(context->block + index, 0, 64U - index);
        transform(context, context->block);
        index = 0;
    }
    memset(context->block + index, 0, 56U - index);
    for (size_t offset = 0; offset < 8; ++offset) {
        context->block[63U - offset] = (uint8_t)(context->bit_count >> (offset * 8U));
    }
    transform(context, context->block);
    for (size_t word = 0; word < 8; ++word) {
        write_big_endian(digest + (word * 4U), context->state[word]);
    }
}
