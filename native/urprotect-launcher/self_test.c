#include "sha256.h"
#include "miniz_tinfl.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static void write_message(const char *message)
{
    size_t length = strlen(message);
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(STDOUT_FILENO, message + offset, length - offset);
        if (written <= 0) {
            return;
        }
        offset += (size_t)written;
    }
}

static int digest_matches(const uint8_t *input, size_t input_size, const uint8_t expected[32])
{
    uint8_t digest[32];
    urp_sha256_context context;
    urp_sha256_init(&context);
    size_t first = input_size < 17U ? input_size : 17U;
    urp_sha256_update(&context, input, first);
    urp_sha256_update(&context, input + first, input_size - first);
    urp_sha256_final(&context, digest);
    return memcmp(digest, expected, 32U) == 0;
}

static int inflater_matches(void)
{
    static const uint8_t encoded[] = {
        0xCBU, 0x48U, 0xCDU, 0xC9U, 0xC9U, 0x57U, 0x28U,
        0xCFU, 0x2FU, 0xCAU, 0x49U, 0x01U, 0x00U,
    };
    static const uint8_t expected[] = "hello world";
    uint8_t output[sizeof(expected) - 1U];
    tinfl_decompressor decompressor;
    tinfl_init(&decompressor);
    size_t input_size = sizeof(encoded);
    size_t output_size = sizeof(output);
    tinfl_status status = tinfl_decompress(
        &decompressor,
        encoded,
        &input_size,
        output,
        output,
        &output_size,
        TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
    return status == TINFL_STATUS_DONE
        && input_size == sizeof(encoded)
        && output_size == sizeof(output)
        && memcmp(output, expected, sizeof(output)) == 0;
}

int main(void)
{
    static const uint8_t empty_digest[32] = {
        0xE3U, 0xB0U, 0xC4U, 0x42U, 0x98U, 0xFCU, 0x1CU, 0x14U,
        0x9AU, 0xFBU, 0xF4U, 0xC8U, 0x99U, 0x6FU, 0xB9U, 0x24U,
        0x27U, 0xAEU, 0x41U, 0xE4U, 0x64U, 0x9BU, 0x93U, 0x4CU,
        0xA4U, 0x95U, 0x99U, 0x1BU, 0x78U, 0x52U, 0xB8U, 0x55U,
    };
    static const uint8_t abc_digest[32] = {
        0xBAU, 0x78U, 0x16U, 0xBFU, 0x8FU, 0x01U, 0xCFU, 0xEAU,
        0x41U, 0x41U, 0x40U, 0xDEU, 0x5DU, 0xAEU, 0x22U, 0x23U,
        0xB0U, 0x03U, 0x61U, 0xA3U, 0x96U, 0x17U, 0x7AU, 0x9CU,
        0xB4U, 0x10U, 0xFFU, 0x61U, 0xF2U, 0x00U, 0x15U, 0xADU,
    };
    static const uint8_t long_digest[32] = {
        0x41U, 0xEDU, 0xECU, 0xE4U, 0x2DU, 0x63U, 0xE8U, 0xD9U,
        0xBFU, 0x51U, 0x5AU, 0x9BU, 0xA6U, 0x93U, 0x2EU, 0x1CU,
        0x20U, 0xCBU, 0xC9U, 0xF5U, 0xA5U, 0xD1U, 0x34U, 0x64U,
        0x5AU, 0xDBU, 0x5DU, 0xB1U, 0xB9U, 0x73U, 0x7EU, 0xA3U,
    };
    uint8_t long_input[1000];
    memset(long_input, 'a', sizeof(long_input));

    static const uint8_t empty_input[1] = {0};
    int empty_ok = digest_matches(empty_input, 0U, empty_digest);
    int abc_ok = digest_matches((const uint8_t *)"abc", 3U, abc_digest);
    int long_ok = digest_matches(long_input, sizeof(long_input), long_digest);
    int inflater_ok = inflater_matches();
    int passed = empty_ok && abc_ok && long_ok && inflater_ok;
    if (!empty_ok) {
        write_message("empty SHA-256 failed\n");
    }
    if (!abc_ok) {
        write_message("abc SHA-256 failed\n");
    }
    if (!long_ok) {
        write_message("long SHA-256 failed\n");
    }
    if (!inflater_ok) {
        write_message("raw inflater failed\n");
    }
    static const char success[] = "native launcher self-test: PASS\n";
    static const char failure[] = "native launcher self-test: FAIL\n";
    const char *message = passed ? success : failure;
    write_message(message);
    return passed ? 0 : 1;
}
