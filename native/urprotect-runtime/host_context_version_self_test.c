#include "urp/host_adapter.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DT_NULL 0U
#define DT_NEEDED 1U
#define DT_HASH 4U
#define DT_STRTAB 5U
#define DT_SYMBOLIC 16U
#define DT_GNU_HASH UINT64_C(0x6ffffef5)
#define DT_VERSYM UINT64_C(0x6ffffff0)
#define DT_VERDEF UINT64_C(0x6ffffffc)
#define DT_VERNEED UINT64_C(0x6ffffffe)
#define DT_VERNEEDNUM UINT64_C(0x6fffffff)
#define MAX_HASH_CHAIN_TEST_STEPS UINT64_C(1048576)

typedef struct dynamic_tags {
    size_t version_symbol_tag_offset;
    size_t version_symbol_value_offset;
    size_t version_need_tag_offset;
    size_t version_need_value_offset;
    size_t version_need_count_value_offset;
    size_t needed_name_value_offset;
    size_t gnu_hash_value_offset;
    size_t terminator_tag_offset;
    uint64_t version_need_address;
    uint64_t string_table_address;
    uint64_t needed_name_offset;
    uint64_t gnu_hash_address;
    int has_version_symbol;
    int has_gnu_hash;
    int has_version_need;
    int has_version_need_count;
    int has_needed_name;
    int has_string_table;
} dynamic_tags;

static uint16_t read_u16(const uint8_t *bytes)
{
    return (uint16_t)bytes[0] | (uint16_t)((uint16_t)bytes[1] << 8U);
}

static uint32_t read_u32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0]
        | ((uint32_t)bytes[1] << 8U)
        | ((uint32_t)bytes[2] << 16U)
        | ((uint32_t)bytes[3] << 24U);
}

static uint64_t read_u64(const uint8_t *bytes)
{
    uint64_t value = 0U;
    for (size_t index = 0U; index < 8U; ++index) {
        value |= (uint64_t)bytes[index] << (index * 8U);
    }
    return value;
}

static void write_u16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8U);
}

static void write_u32(uint8_t *bytes, uint32_t value)
{
    for (size_t index = 0U; index < 4U; ++index) {
        bytes[index] = (uint8_t)(value >> (index * 8U));
    }
}

static void write_u64(uint8_t *bytes, uint64_t value)
{
    for (size_t index = 0U; index < 8U; ++index) {
        bytes[index] = (uint8_t)(value >> (index * 8U));
    }
}

static int read_file(const char *path, uint8_t **bytes_out, size_t *size_out)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL || fseek(file, 0L, SEEK_END) != 0) {
        if (file != NULL) {
            (void)fclose(file);
        }
        return 0;
    }

    long length = ftell(file);
    if (length <= 0L || fseek(file, 0L, SEEK_SET) != 0) {
        (void)fclose(file);
        return 0;
    }
    uint8_t *bytes = (uint8_t *)malloc((size_t)length);
    if (bytes == NULL) {
        (void)fclose(file);
        return 0;
    }
    size_t length_size = (size_t)length;
    if (fread(bytes, 1U, length_size, file) != length_size || ferror(file) != 0) {
        free(bytes);
        (void)fclose(file);
        return 0;
    }
    (void)fclose(file);
    *bytes_out = bytes;
    *size_out = length_size;
    return 1;
}

static int find_dynamic_tags(uint8_t *image, size_t image_size, dynamic_tags *tags)
{
    if (image_size < 64U || read_u16(image + 54U) != 56U) {
        return 0;
    }

    uint64_t program_header_offset = read_u64(image + 32U);
    uint16_t program_header_count = read_u16(image + 56U);
    if (program_header_offset > (uint64_t)image_size
        || (uint64_t)program_header_count * 56U
            > (uint64_t)image_size - program_header_offset) {
        return 0;
    }

    uint64_t dynamic_offset = 0U;
    uint64_t dynamic_size = 0U;
    for (uint16_t index = 0U; index < program_header_count; ++index) {
        const uint8_t *header = image
            + (size_t)(program_header_offset + (uint64_t)index * 56U);
        if (read_u32(header) == 2U) {
            dynamic_offset = read_u64(header + 8U);
            dynamic_size = read_u64(header + 32U);
            break;
        }
    }
    if (dynamic_offset > (uint64_t)image_size
        || dynamic_size > (uint64_t)image_size - dynamic_offset
        || dynamic_size % 16U != 0U) {
        return 0;
    }

    memset(tags, 0, sizeof(*tags));
    size_t dynamic_entry_count = (size_t)(dynamic_size / 16U);
    int terminated = 0;
    for (size_t index = 0U; index < dynamic_entry_count; ++index) {
        size_t entry_offset = (size_t)dynamic_offset + index * 16U;
        uint8_t *entry = image + entry_offset;
        uint64_t tag = read_u64(entry);
        if (tag == DT_NULL) {
            tags->terminator_tag_offset = entry_offset;
            terminated = 1;
            break;
        }
        switch (tag) {
        case DT_NEEDED:
            if (tags->has_needed_name != 0) {
                return 0;
            }
            tags->needed_name_value_offset = entry_offset + 8U;
            tags->needed_name_offset = read_u64(entry + 8U);
            tags->has_needed_name = 1;
            break;
        case DT_STRTAB:
            if (tags->has_string_table != 0) {
                return 0;
            }
            tags->string_table_address = read_u64(entry + 8U);
            tags->has_string_table = 1;
            break;
        case DT_GNU_HASH:
            if (tags->has_gnu_hash != 0) {
                return 0;
            }
            tags->gnu_hash_value_offset = entry_offset + 8U;
            tags->gnu_hash_address = read_u64(entry + 8U);
            tags->has_gnu_hash = 1;
            break;
        case DT_VERSYM:
            if (tags->has_version_symbol != 0) {
                return 0;
            }
            tags->version_symbol_tag_offset = entry_offset;
            tags->version_symbol_value_offset = entry_offset + 8U;
            tags->has_version_symbol = 1;
            break;
        case DT_VERNEED:
            if (tags->has_version_need != 0) {
                return 0;
            }
            tags->version_need_tag_offset = entry_offset;
            tags->version_need_value_offset = entry_offset + 8U;
            tags->version_need_address = read_u64(entry + 8U);
            tags->has_version_need = 1;
            break;
        case DT_VERNEEDNUM:
            if (tags->has_version_need_count != 0) {
                return 0;
            }
            tags->version_need_count_value_offset = entry_offset + 8U;
            tags->has_version_need_count = 1;
            break;
        default:
            break;
        }
    }

    return terminated != 0 && tags->has_needed_name != 0
        && tags->has_string_table != 0 && tags->has_version_symbol != 0
        && tags->has_gnu_hash != 0
        && tags->has_version_need != 0 && tags->has_version_need_count != 0;
}

static int virtual_to_file(
    const uint8_t *image,
    size_t image_size,
    uint64_t virtual_address,
    size_t length,
    size_t *file_offset_out)
{
    uint64_t program_header_offset = read_u64(image + 32U);
    uint16_t program_header_count = read_u16(image + 56U);
    if (program_header_offset > (uint64_t)image_size
        || (uint64_t)program_header_count * 56U
            > (uint64_t)image_size - program_header_offset) {
        return 0;
    }
    for (uint16_t index = 0U; index < program_header_count; ++index) {
        const uint8_t *header = image
            + (size_t)(program_header_offset + (uint64_t)index * 56U);
        if (read_u32(header) != 1U) {
            continue;
        }

        uint64_t segment_virtual_address = read_u64(header + 16U);
        uint64_t segment_file_offset = read_u64(header + 8U);
        uint64_t segment_file_size = read_u64(header + 32U);
        if (virtual_address < segment_virtual_address) {
            continue;
        }
        uint64_t delta = virtual_address - segment_virtual_address;
        if (delta > segment_file_size
            || (uint64_t)length > segment_file_size - delta
            || segment_file_offset > (uint64_t)image_size
            || delta > (uint64_t)image_size - segment_file_offset) {
            continue;
        }
        uint64_t file_offset = segment_file_offset + delta;
        if ((uint64_t)length > (uint64_t)image_size - file_offset) {
            continue;
        }
        if (file_offset_out != NULL) {
            *file_offset_out = (size_t)file_offset;
        }
        return 1;
    }
    return 0;
}

static int gnu_hash_symbol_count(
    const uint8_t *image,
    size_t image_size,
    uint64_t hash_address,
    uint64_t *symbol_count_out)
{
    size_t hash_file_offset;
    if (!virtual_to_file(image, image_size, hash_address, 16U, &hash_file_offset)) {
        return 0;
    }

    uint64_t bucket_count = read_u32(image + hash_file_offset);
    uint64_t first_hashed_symbol = read_u32(image + hash_file_offset + 4U);
    uint64_t bloom_word_count = read_u32(image + hash_file_offset + 8U);
    if (bucket_count == 0U || first_hashed_symbol == 0U || bloom_word_count == 0U) {
        return 0;
    }

    uint64_t bucket_address = hash_address + 16U + bloom_word_count * sizeof(uint64_t);
    uint64_t bucket_size = bucket_count * sizeof(uint32_t);
    uint64_t chain_address = bucket_address + bucket_size;
    if (bucket_size > SIZE_MAX) {
        return 0;
    }
    size_t bucket_file_offset;
    if (!virtual_to_file(
            image,
            image_size,
            bucket_address,
            (size_t)bucket_size,
            &bucket_file_offset)) {
        return 0;
    }

    uint64_t maximum_symbol = first_hashed_symbol - 1U;
    int found_symbol = 0;
    uint64_t max_chain_steps = (uint64_t)(image_size / sizeof(uint32_t));
    for (uint64_t bucket_index = 0U; bucket_index < bucket_count; ++bucket_index) {
        size_t bucket_entry_offset = bucket_file_offset
            + (size_t)(bucket_index * sizeof(uint32_t));
        uint64_t symbol_index = read_u32(image + bucket_entry_offset);
        if (symbol_index == 0U) {
            continue;
        }
        if (symbol_index < first_hashed_symbol) {
            return 0;
        }
        found_symbol = 1;

        int terminated = 0;
        for (uint64_t step = 0U; step < max_chain_steps; ++step) {
            uint64_t chain_offset = (symbol_index - first_hashed_symbol)
                * sizeof(uint32_t);
            size_t chain_file_offset;
            if (!virtual_to_file(
                    image,
                    image_size,
                    chain_address + chain_offset,
                    sizeof(uint32_t),
                    &chain_file_offset)) {
                return 0;
            }
            uint32_t chain = read_u32(image + chain_file_offset);
            if (symbol_index > maximum_symbol) {
                maximum_symbol = symbol_index;
            }
            if ((chain & 1U) != 0U) {
                terminated = 1;
                break;
            }
            ++symbol_index;
        }
        if (terminated == 0) {
            return 0;
        }
    }

    *symbol_count_out = found_symbol != 0 ? maximum_symbol + 1U : first_hashed_symbol;
    return *symbol_count_out != 0U;
}

static int find_gnu_hash_chain_layout(
    const uint8_t *image,
    size_t image_size,
    uint64_t hash_address,
    size_t *bucket_file_offset_out,
    uint64_t *bucket_count_out,
    uint64_t *first_hashed_symbol_out,
    uint64_t *chain_address_out)
{
    size_t header_file_offset;
    if (!virtual_to_file(image, image_size, hash_address, 16U, &header_file_offset)) {
        return 0;
    }

    uint64_t bucket_count = read_u32(image + header_file_offset);
    uint64_t first_hashed_symbol = read_u32(image + header_file_offset + 4U);
    uint64_t bloom_word_count = read_u32(image + header_file_offset + 8U);
    uint64_t bucket_address = hash_address + 16U + bloom_word_count * sizeof(uint64_t);
    uint64_t bucket_size = bucket_count * sizeof(uint32_t);
    uint64_t chain_address = bucket_address + bucket_size;
    if (bucket_count == 0U || first_hashed_symbol == 0U || bucket_size > SIZE_MAX
        || !virtual_to_file(
            image,
            image_size,
            bucket_address,
            (size_t)bucket_size,
            bucket_file_offset_out)) {
        return 0;
    }

    *bucket_count_out = bucket_count;
    *first_hashed_symbol_out = first_hashed_symbol;
    *chain_address_out = chain_address;
    return 1;
}

static int find_unterminated_chain_boundary(
    const uint8_t *image,
    size_t image_size,
    uint64_t chain_address,
    uint64_t *last_chain_address_out,
    size_t *last_chain_file_offset_out)
{
    uint64_t program_header_offset = read_u64(image + 32U);
    uint16_t program_header_count = read_u16(image + 56U);
    if (program_header_offset > (uint64_t)image_size
        || (uint64_t)program_header_count * 56U
            > (uint64_t)image_size - program_header_offset) {
        return 0;
    }

    uint64_t maximum_load_end = 0U;
    for (uint16_t index = 0U; index < program_header_count; ++index) {
        const uint8_t *header = image
            + (size_t)(program_header_offset + (uint64_t)index * 56U);
        if (read_u32(header) != 1U) {
            continue;
        }
        uint64_t virtual_address = read_u64(header + 16U);
        uint64_t file_offset = read_u64(header + 8U);
        uint64_t file_size = read_u64(header + 32U);
        if (file_offset > (uint64_t)image_size
            || file_size > (uint64_t)image_size - file_offset
            || file_size > UINT64_MAX - virtual_address) {
            return 0;
        }
        uint64_t segment_end = virtual_address + file_size;
        if (segment_end > maximum_load_end) {
            maximum_load_end = segment_end;
        }
    }

    if (maximum_load_end < sizeof(uint32_t)
        || maximum_load_end - sizeof(uint32_t) < chain_address) {
        return 0;
    }
    if (chain_address > UINT64_MAX - sizeof(uint32_t)) {
        return 0;
    }
    uint64_t chain_address_next = chain_address + sizeof(uint32_t);
    uint64_t candidate_address = maximum_load_end - sizeof(uint32_t);
    uint64_t alignment_delta = (candidate_address - chain_address) % sizeof(uint32_t);
    candidate_address -= alignment_delta;
    for (uint64_t step = 0U; step < MAX_HASH_CHAIN_TEST_STEPS; ++step) {
        if (virtual_to_file(
                image,
                image_size,
                candidate_address,
                sizeof(uint32_t),
                NULL)
            && candidate_address <= UINT64_MAX - sizeof(uint32_t)
            && !virtual_to_file(
                image,
                image_size,
                candidate_address + sizeof(uint32_t),
                sizeof(uint32_t),
                NULL)) {
            *last_chain_address_out = candidate_address;
            return virtual_to_file(
                image,
                image_size,
                candidate_address,
                sizeof(uint32_t),
                last_chain_file_offset_out);
        }
        if (candidate_address < chain_address_next) {
            break;
        }
        candidate_address -= sizeof(uint32_t);
    }
    return 0;
}

static int find_mapped_short_versym_range(
    const uint8_t *image,
    size_t image_size,
    uint64_t full_table_size,
    uint64_t *address_out)
{
    uint64_t program_header_offset = read_u64(image + 32U);
    uint16_t program_header_count = read_u16(image + 56U);
    if (program_header_offset > (uint64_t)image_size
        || (uint64_t)program_header_count * 56U
            > (uint64_t)image_size - program_header_offset
        || full_table_size > (uint64_t)SIZE_MAX) {
        return 0;
    }

    for (uint16_t index = 0U; index < program_header_count; ++index) {
        const uint8_t *header = image
            + (size_t)(program_header_offset + (uint64_t)index * 56U);
        if (read_u32(header) != 1U) {
            continue;
        }
        uint64_t segment_virtual_address = read_u64(header + 16U);
        uint64_t segment_file_size = read_u64(header + 32U);
        if (segment_file_size < sizeof(uint16_t)
            || segment_file_size - sizeof(uint16_t)
                > UINT64_MAX - segment_virtual_address) {
            continue;
        }
        uint64_t candidate_address = segment_virtual_address
            + segment_file_size - sizeof(uint16_t);
        size_t candidate_file_offset;
        if (virtual_to_file(
                image,
                image_size,
                candidate_address,
                sizeof(uint16_t),
                &candidate_file_offset)
            && !virtual_to_file(
                image,
                image_size,
                candidate_address,
                (size_t)full_table_size,
                &candidate_file_offset)) {
            *address_out = candidate_address;
            return 1;
        }
    }
    return 0;
}

static int expect_reject(
    urp_host_adapter_v1 *adapter,
    const uint8_t *image,
    size_t image_size,
    urp_status expected_status)
{
    static size_t negative_case_number;
    ++negative_case_number;
    urp_image_handle handle = UINT64_C(0xfeedface);
    urp_status status = adapter->context.load_image(
        adapter->context.userdata,
        image,
        image_size,
        URP_LOAD_IMAGE_IMMUTABLE,
        &handle);
    if (status == expected_status && handle == 0U) {
        return 1;
    }
    (void)fprintf(
        stderr,
        "version negative case %zu: status=%d, handle=%llu, expected status=%d and zero handle\n",
        negative_case_number,
        status,
        (unsigned long long)handle,
        expected_status);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        return 2;
    }
    uint8_t *source = NULL;
    size_t source_size = 0U;
    if (!read_file(argv[1], &source, &source_size)) {
        (void)fputs("version self-test: failed to read fixture\n", stderr);
        return 1;
    }

    dynamic_tags tags;
    if (!find_dynamic_tags(source, source_size, &tags)) {
        (void)fputs("version self-test: missing required dynamic tags\n", stderr);
        free(source);
        return 1;
    }

    urp_host_adapter_v1 adapter;
    urp_host_adapter_init(&adapter);
    urp_image_handle handle = 0U;
    urp_status initial_load_status = adapter.context.load_image(
            adapter.context.userdata,
            source,
            source_size,
            URP_LOAD_IMAGE_IMMUTABLE,
            &handle);
    if (initial_load_status != URP_STATUS_OK || handle == 0U) {
        (void)fprintf(
            stderr,
            "version self-test: positive fixture load returned %d, handle=%llu\n",
            initial_load_status,
            (unsigned long long)handle);
        free(source);
        return 1;
    }
    urp_status initial_release_status = adapter.context.release_image(
        adapter.context.userdata,
        handle);
    if (initial_release_status != URP_STATUS_OK) {
        (void)fprintf(
            stderr,
            "version self-test: positive fixture release returned %d\n",
            initial_release_status);
        free(source);
        return 1;
    }

    uint8_t *mutant = (uint8_t *)malloc(source_size);
    if (mutant == NULL) {
        (void)fputs("version self-test: failed to allocate mutation buffer\n", stderr);
        free(source);
        return 1;
    }

    size_t version_need_file_offset;
    if (!virtual_to_file(
            source,
            source_size,
            tags.version_need_address,
            16U,
            &version_need_file_offset)) {
        (void)fputs("version self-test: DT_VERNEED mapping is invalid\n", stderr);
        free(mutant);
        free(source);
        return 1;
    }
    uint64_t auxiliary_address = tags.version_need_address
        + (uint64_t)read_u32(source + version_need_file_offset + 8U);
    size_t auxiliary_file_offset;
    if (!virtual_to_file(source, source_size, auxiliary_address, 16U, &auxiliary_file_offset)) {
        (void)fputs("version self-test: Vernaux mapping is invalid\n", stderr);
        free(mutant);
        free(source);
        return 1;
    }
    size_t gnu_hash_file_offset;
    if (!virtual_to_file(
            source,
            source_size,
            tags.gnu_hash_address,
            16U,
            &gnu_hash_file_offset)) {
        (void)fputs("version self-test: DT_GNU_HASH mapping is invalid\n", stderr);
        free(mutant);
        free(source);
        return 1;
    }
    size_t gnu_bucket_file_offset;
    size_t last_chain_file_offset = 0U;
    uint64_t gnu_bucket_count;
    uint64_t first_hashed_symbol;
    uint64_t chain_address;
    uint64_t last_chain_address;
    if (!find_gnu_hash_chain_layout(
            source,
            source_size,
            tags.gnu_hash_address,
            &gnu_bucket_file_offset,
            &gnu_bucket_count,
            &first_hashed_symbol,
            &chain_address)
        || gnu_bucket_count == 0U
        || !find_unterminated_chain_boundary(
            source,
            source_size,
            chain_address,
            &last_chain_address,
            &last_chain_file_offset)
        || last_chain_address < chain_address
        || (last_chain_address - chain_address) % sizeof(uint32_t) != 0U) {
        (void)fputs("version self-test: failed to derive a mapped GNU-hash chain boundary\n", stderr);
        free(mutant);
        free(source);
        return 1;
    }
    uint64_t last_chain_symbol_index = first_hashed_symbol
        + (last_chain_address - chain_address) / sizeof(uint32_t);
    if (last_chain_symbol_index > UINT32_MAX
        || last_chain_symbol_index > MAX_HASH_CHAIN_TEST_STEPS) {
        (void)fprintf(
            stderr,
            "version self-test: GNU-hash terminal index %llu exceeds test bound\n",
            (unsigned long long)last_chain_symbol_index);
        free(mutant);
        free(source);
        return 1;
    }
    uint64_t dynamic_symbol_count;
    uint64_t short_versym_address;
    size_t original_versym_file_offset;
    if (!gnu_hash_symbol_count(
            source,
            source_size,
            tags.gnu_hash_address,
            &dynamic_symbol_count)
        || dynamic_symbol_count <= 1U
        || dynamic_symbol_count > UINT64_MAX / sizeof(uint16_t)
        || !virtual_to_file(
            source,
            source_size,
            read_u64(source + tags.version_symbol_value_offset),
            (size_t)(dynamic_symbol_count * sizeof(uint16_t)),
            &original_versym_file_offset)
        || !find_mapped_short_versym_range(
            source,
            source_size,
            dynamic_symbol_count * sizeof(uint16_t),
            &short_versym_address)) {
        (void)fputs("version self-test: failed to derive bounded GNU-hash/VERSYM ranges\n", stderr);
        free(mutant);
        free(source);
        return 1;
    }
    (void)original_versym_file_offset;
    uint64_t needed_string_address = tags.string_table_address + tags.needed_name_offset;
    size_t needed_string_file_offset;
    if (tags.needed_name_offset > UINT32_MAX
        || !virtual_to_file(
            source,
            source_size,
            needed_string_address,
            sizeof("libc.so.6"),
            &needed_string_file_offset)
        || memcmp(source + needed_string_file_offset, "libc.so.6", sizeof("libc.so.6")) != 0) {
        (void)fputs("version self-test: libc.so.6 dynamic-string mapping is invalid\n", stderr);
        free(mutant);
        free(source);
        return 1;
    }

    /* A version requirement may name only the single accepted DT_NEEDED libc. */
    memcpy(mutant, source, source_size);
    write_u32(mutant + version_need_file_offset + 4U, 0U);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_UNSUPPORTED)) {
        free(mutant);
        free(source);
        return 1;
    }

    /* Versioned imports are limited to the native glibc SONAME, not other libc names. */
    memcpy(mutant, source, source_size);
    mutant[needed_string_file_offset + 7U] = 0U;
    write_u32(
        mutant + version_need_file_offset + 4U,
        (uint32_t)tags.needed_name_offset);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_UNSUPPORTED)) {
        free(mutant);
        free(source);
        return 1;
    }

    /* Out-of-image version chains and inconsistent counts fail before dlopen. */
    memcpy(mutant, source, source_size);
    write_u64(mutant + tags.version_need_value_offset, UINT64_MAX - 7U);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_LOAD_FAILED)) {
        free(mutant);
        free(source);
        return 1;
    }

    memcpy(mutant, source, source_size);
    write_u64(mutant + tags.version_symbol_value_offset, UINT64_MAX - 7U);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_LOAD_FAILED)) {
        free(mutant);
        free(source);
        return 1;
    }

    /* A pointer may be mapped for two bytes yet too short for the full VERSYM table. */
    memcpy(mutant, source, source_size);
    write_u64(mutant + tags.version_symbol_value_offset, short_versym_address);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_LOAD_FAILED)) {
        free(mutant);
        free(source);
        return 1;
    }

    memcpy(mutant, source, source_size);
    write_u64(mutant + tags.gnu_hash_value_offset, UINT64_MAX - 7U);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_LOAD_FAILED)) {
        free(mutant);
        free(source);
        return 1;
    }

    memcpy(mutant, source, source_size);
    write_u32(mutant + gnu_hash_file_offset, UINT32_MAX);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_LOAD_FAILED)) {
        free(mutant);
        free(source);
        return 1;
    }

    /* Clear a terminal chain bit at the mapped boundary so the next word is unmapped. */
    memcpy(mutant, source, source_size);
    write_u32(mutant + gnu_bucket_file_offset, (uint32_t)last_chain_symbol_index);
    write_u32(mutant + last_chain_file_offset, 0U);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_LOAD_FAILED)) {
        free(mutant);
        free(source);
        return 1;
    }

    memcpy(mutant, source, source_size);
    write_u32(mutant + auxiliary_file_offset, 0U);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_LOAD_FAILED)) {
        free(mutant);
        free(source);
        return 1;
    }

    memcpy(mutant, source, source_size);
    write_u16(mutant + auxiliary_file_offset + 6U, UINT16_C(0x8002));
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_LOAD_FAILED)) {
        free(mutant);
        free(source);
        return 1;
    }

    memcpy(mutant, source, source_size);
    write_u16(mutant + auxiliary_file_offset + 4U, 2U);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_UNSUPPORTED)) {
        free(mutant);
        free(source);
        return 1;
    }

    memcpy(mutant, source, source_size);
    write_u32(mutant + auxiliary_file_offset + 12U, 16U);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_LOAD_FAILED)) {
        free(mutant);
        free(source);
        return 1;
    }

    memcpy(mutant, source, source_size);
    write_u16(mutant + version_need_file_offset + 2U, 2U);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_LOAD_FAILED)) {
        free(mutant);
        free(source);
        return 1;
    }

    memcpy(mutant, source, source_size);
    write_u32(mutant + version_need_file_offset + 12U, 16U);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_LOAD_FAILED)) {
        free(mutant);
        free(source);
        return 1;
    }

    memcpy(mutant, source, source_size);
    write_u64(mutant + tags.version_need_count_value_offset, 0U);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_UNSUPPORTED)) {
        free(mutant);
        free(source);
        return 1;
    }

    memcpy(mutant, source, source_size);
    write_u64(mutant + tags.version_need_count_value_offset, UINT64_MAX);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_LOAD_FAILED)) {
        free(mutant);
        free(source);
        return 1;
    }

    /* The proven runtime slice derives the VERSYM bound from GNU_HASH only. */
    memcpy(mutant, source, source_size);
    write_u64(mutant + tags.terminator_tag_offset, DT_HASH);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_UNSUPPORTED)) {
        free(mutant);
        free(source);
        return 1;
    }

    memcpy(mutant, source, source_size);
    write_u64(mutant + tags.terminator_tag_offset, DT_SYMBOLIC);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_UNSUPPORTED)) {
        free(mutant);
        free(source);
        return 1;
    }

    memcpy(mutant, source, source_size);
    write_u32(mutant + version_need_file_offset + 8U, UINT32_MAX);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_LOAD_FAILED)) {
        free(mutant);
        free(source);
        return 1;
    }

    /* The dynamic symbol-version index table is part of the accepted tuple. */
    memcpy(mutant, source, source_size);
    write_u64(mutant + tags.version_symbol_tag_offset, DT_NULL);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_UNSUPPORTED)) {
        free(mutant);
        free(source);
        return 1;
    }

    /* Versioned exported definitions, including a versioned entry, stay out of v1. */
    memcpy(mutant, source, source_size);
    write_u64(mutant + tags.terminator_tag_offset, DT_VERDEF);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_UNSUPPORTED)) {
        free(mutant);
        free(source);
        return 1;
    }

    free(mutant);
    free(source);
    puts("HostContext libc symbol-version self-test: PASS");
    return 0;
}
