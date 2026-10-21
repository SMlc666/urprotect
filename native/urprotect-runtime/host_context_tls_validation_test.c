#include "host_image_validation.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ELF_HEADER_SIZE 64U
#define PROGRAM_HEADER_SIZE 56U
#define DYNAMIC_ENTRY_SIZE 16U
#define SYMBOL_SIZE 24U
#define RELA_ENTRY_SIZE 24U
#define PT_LOAD 1U
#define PT_DYNAMIC 2U
#define PT_TLS 7U
#define DT_NEEDED 1U
#define DT_PLTRELSZ 2U
#define DT_STRTAB 5U
#define DT_SYMTAB 6U
#define DT_RELA 7U
#define DT_RELASZ 8U
#define DT_SYMENT 11U
#define DT_STRSZ 10U
#define DT_JMPREL 23U
#define DT_VERNEED UINT64_C(0x6ffffffe)
#define R_AARCH64_TLS_DTPMOD64 1028U
#define R_AARCH64_TLS_DTPREL64 1029U
#define R_AARCH64_TLS_TPREL64 1030U
#define R_AARCH64_TLSDESC 1031U
#define STT_TLS 6U
#define SHN_UNDEF 0U

struct dynamic_facts {
    uint64_t rela_address;
    uint64_t rela_size;
    uint64_t jmprel_address;
    uint64_t pltrelsz;
    uint64_t symtab_address;
    uint64_t syment;
    uint64_t strtab_address;
    uint64_t strsz;
    uint64_t verneed_address;
    size_t needed_value_offsets[4];
    uint64_t needed_name_offsets[4];
    size_t needed_count;
};

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
    for (size_t index = 0U; index < sizeof(uint64_t); ++index) {
        value |= (uint64_t)bytes[index] << (index * 8U);
    }
    return value;
}

static void write_u32(uint8_t *bytes, uint32_t value)
{
    for (size_t index = 0U; index < sizeof(uint32_t); ++index) {
        bytes[index] = (uint8_t)(value >> (index * 8U));
    }
}

static void write_u64(uint8_t *bytes, uint64_t value)
{
    for (size_t index = 0U; index < sizeof(uint64_t); ++index) {
        bytes[index] = (uint8_t)(value >> (index * 8U));
    }
}

static int read_file(const char *path, uint8_t **bytes_out, size_t *size_out)
{
    FILE *stream = fopen(path, "rb");
    if (stream == NULL || fseek(stream, 0L, SEEK_END) != 0) {
        if (stream != NULL) {
            (void)fclose(stream);
        }
        return 0;
    }

    long length = ftell(stream);
    if (length <= 0L || (uintmax_t)length > (uintmax_t)SIZE_MAX
        || fseek(stream, 0L, SEEK_SET) != 0) {
        (void)fclose(stream);
        return 0;
    }
    size_t size = (size_t)length;
    uint8_t *bytes = (uint8_t *)malloc(size);
    if (bytes == NULL) {
        (void)fclose(stream);
        return 0;
    }
    size_t read_size = fread(bytes, 1U, size, stream);
    int close_status = fclose(stream);
    if (read_size != size || close_status != 0) {
        free(bytes);
        return 0;
    }

    *bytes_out = bytes;
    *size_out = size;
    return 1;
}

static int program_header_table(
    const uint8_t *image,
    size_t image_size,
    uint64_t *offset_out,
    uint16_t *count_out)
{
    if (image_size < ELF_HEADER_SIZE
        || image[0] != 0x7fU || image[1] != 'E' || image[2] != 'L' || image[3] != 'F'
        || image[4] != 2U || image[5] != 1U
        || read_u16(image + 54U) != PROGRAM_HEADER_SIZE) {
        return 0;
    }
    uint64_t offset = read_u64(image + 32U);
    uint16_t count = read_u16(image + 56U);
    if (count == 0U || offset > (uint64_t)image_size
        || (uint64_t)count * PROGRAM_HEADER_SIZE > (uint64_t)image_size - offset) {
        return 0;
    }
    *offset_out = offset;
    *count_out = count;
    return 1;
}

static int map_virtual_range(
    const uint8_t *image,
    size_t image_size,
    uint64_t program_header_offset,
    uint16_t program_header_count,
    uint64_t address,
    uint64_t length,
    size_t *file_offset_out)
{
    size_t matches = 0U;
    size_t resolved = 0U;
    for (uint16_t index = 0U; index < program_header_count; ++index) {
        uint64_t header_offset = program_header_offset + (uint64_t)index * PROGRAM_HEADER_SIZE;
        const uint8_t *header = image + (size_t)header_offset;
        if (read_u32(header) != PT_LOAD) {
            continue;
        }

        uint64_t virtual_address = read_u64(header + 16U);
        uint64_t file_offset = read_u64(header + 8U);
        uint64_t file_size = read_u64(header + 32U);
        if (address < virtual_address) {
            continue;
        }
        uint64_t delta = address - virtual_address;
        if (delta > file_size || length > file_size - delta
            || file_offset > (uint64_t)image_size
            || delta > (uint64_t)image_size - file_offset) {
            continue;
        }
        uint64_t candidate = file_offset + delta;
        if (length > (uint64_t)image_size - candidate || candidate > (uint64_t)SIZE_MAX) {
            continue;
        }
        resolved = (size_t)candidate;
        ++matches;
    }
    if (matches != 1U) {
        return 0;
    }
    if (file_offset_out != NULL) {
        *file_offset_out = resolved;
    }
    return 1;
}

static int find_dynamic_facts(
    const uint8_t *image,
    size_t image_size,
    struct dynamic_facts *facts)
{
    uint64_t phoff;
    uint16_t phnum;
    if (!program_header_table(image, image_size, &phoff, &phnum)) {
        return 0;
    }
    memset(facts, 0, sizeof(*facts));
    size_t dynamic_count = 0U;
    int terminated = 0;
    for (uint16_t index = 0U; index < phnum; ++index) {
        uint64_t header_offset = phoff + (uint64_t)index * PROGRAM_HEADER_SIZE;
        const uint8_t *header = image + (size_t)header_offset;
        if (read_u32(header) != PT_DYNAMIC) {
            continue;
        }
        ++dynamic_count;
        uint64_t dynamic_offset = read_u64(header + 8U);
        uint64_t dynamic_size = read_u64(header + 32U);
        if (dynamic_size == 0U || dynamic_size % DYNAMIC_ENTRY_SIZE != 0U
            || dynamic_offset > (uint64_t)image_size
            || dynamic_size > (uint64_t)image_size - dynamic_offset) {
            return 0;
        }
        size_t entry_count = (size_t)(dynamic_size / DYNAMIC_ENTRY_SIZE);
        for (size_t entry_index = 0U; entry_index < entry_count; ++entry_index) {
            size_t entry_offset = (size_t)dynamic_offset + entry_index * DYNAMIC_ENTRY_SIZE;
            const uint8_t *entry = image + entry_offset;
            uint64_t tag = read_u64(entry);
            uint64_t value = read_u64(entry + 8U);
            if (tag == 0U) {
                terminated = 1;
                break;
            }
            switch (tag) {
            case DT_NEEDED:
                if (facts->needed_count >= sizeof(facts->needed_name_offsets)
                    / sizeof(facts->needed_name_offsets[0])) {
                    return 0;
                }
                facts->needed_value_offsets[facts->needed_count] = entry_offset + 8U;
                facts->needed_name_offsets[facts->needed_count] = value;
                ++facts->needed_count;
                break;
            case DT_PLTRELSZ:
                facts->pltrelsz = value;
                break;
            case DT_STRTAB:
                facts->strtab_address = value;
                break;
            case DT_SYMTAB:
                facts->symtab_address = value;
                break;
            case DT_RELA:
                facts->rela_address = value;
                break;
            case DT_RELASZ:
                facts->rela_size = value;
                break;
            case DT_SYMENT:
                facts->syment = value;
                break;
            case DT_STRSZ:
                facts->strsz = value;
                break;
            case DT_JMPREL:
                facts->jmprel_address = value;
                break;
            case DT_VERNEED:
                facts->verneed_address = value;
                break;
            default:
                break;
            }
        }
    }
    return dynamic_count == 1U && terminated != 0;
}

static int find_tls_layout(
    const uint8_t *image,
    size_t image_size,
    uint64_t phoff,
    uint16_t phnum,
    uint64_t *virtual_address_out,
    uint64_t *memory_size_out)
{
    size_t count = 0U;
    for (uint16_t index = 0U; index < phnum; ++index) {
        const uint8_t *header = image + (size_t)(phoff + (uint64_t)index * PROGRAM_HEADER_SIZE);
        if (read_u32(header) != PT_TLS) {
            continue;
        }
        ++count;
        uint64_t file_offset = read_u64(header + 8U);
        uint64_t file_size = read_u64(header + 32U);
        uint64_t memory_size = read_u64(header + 40U);
        if (file_size > memory_size || file_offset > (uint64_t)image_size
            || file_size > (uint64_t)image_size - file_offset) {
            return 0;
        }
        *virtual_address_out = read_u64(header + 16U);
        *memory_size_out = memory_size;
    }
    return count == 1U && *memory_size_out != 0U;
}

static int find_tls_symbol_record(
    const uint8_t *image,
    size_t image_size,
    const struct dynamic_facts *facts,
    uint64_t phoff,
    uint16_t phnum,
    uint32_t wanted_type,
    size_t *symbol_value_offset_out,
    uint64_t *symbol_size_out)
{
    if (facts->syment != SYMBOL_SIZE || facts->symtab_address == 0U) {
        return 0;
    }
    const uint64_t table_addresses[] = {facts->rela_address, facts->jmprel_address};
    const uint64_t table_sizes[] = {facts->rela_size, facts->pltrelsz};
    for (size_t table_index = 0U; table_index < 2U; ++table_index) {
        uint64_t table_size = table_sizes[table_index];
        if (table_size == 0U || table_size % RELA_ENTRY_SIZE != 0U) {
            continue;
        }
        size_t table_offset;
        if (!map_virtual_range(
                image, image_size, phoff, phnum,
                table_addresses[table_index], table_size, &table_offset)) {
            return 0;
        }
        for (uint64_t entry_offset = 0U; entry_offset < table_size; entry_offset += RELA_ENTRY_SIZE) {
            const uint8_t *relocation = image + table_offset + (size_t)entry_offset;
            uint64_t info = read_u64(relocation + 8U);
            if ((uint32_t)info != wanted_type) {
                continue;
            }
            uint64_t symbol_index = info >> 32U;
            if (symbol_index == 0U || symbol_index > UINT64_MAX / facts->syment) {
                return 0;
            }
            uint64_t symbol_delta = symbol_index * facts->syment;
            if (facts->symtab_address > UINT64_MAX - symbol_delta) {
                return 0;
            }
            size_t symbol_offset;
            if (!map_virtual_range(
                    image, image_size, phoff, phnum,
                    facts->symtab_address + symbol_delta, facts->syment, &symbol_offset)) {
                return 0;
            }
            const uint8_t *symbol = image + symbol_offset;
            if ((symbol[4U] & 0x0fU) != STT_TLS || read_u16(symbol + 6U) == SHN_UNDEF) {
                return 0;
            }
            *symbol_value_offset_out = symbol_offset + 8U;
            *symbol_size_out = read_u64(symbol + 16U);
            return 1;
        }
    }
    return 0;
}

static int expect_status(
    const uint8_t *image,
    size_t image_size,
    urp_status expected,
    const char *label)
{
    size_t dependency_count = 0U;
    urp_status status = urp_host_image_validate(image, image_size, &dependency_count);
    if (status == expected) {
        return 1;
    }
    (void)fprintf(stderr, "%s: preflight status %d, expected %d\n", label, status, expected);
    return 0;
}

static int test_tls_symbol_bounds(const char *path, uint32_t relocation_type)
{
    uint8_t *source = NULL;
    uint8_t *mutated = NULL;
    size_t source_size = 0U;
    uint64_t phoff;
    uint16_t phnum;
    uint64_t tls_address = 0U;
    uint64_t tls_size = 0U;
    size_t symbol_value_offset;
    uint64_t symbol_size;
    struct dynamic_facts facts;
    if (!read_file(path, &source, &source_size)
        || !program_header_table(source, source_size, &phoff, &phnum)
        || !find_dynamic_facts(source, source_size, &facts)
        || !find_tls_layout(source, source_size, phoff, phnum, &tls_address, &tls_size)
        || !find_tls_symbol_record(
            source, source_size, &facts, phoff, phnum, relocation_type,
            &symbol_value_offset, &symbol_size)
        || symbol_size == 0U
        || !expect_status(source, source_size, URP_STATUS_OK, "positive TLS symbol")) {
        free(source);
        (void)fprintf(stderr, "TLS symbol-bound fixture is malformed or did not pass: %s\n", path);
        return 0;
    }

    mutated = (uint8_t *)malloc(source_size);
    if (mutated == NULL) {
        free(source);
        return 0;
    }

    /* STT_TLS st_value is a TLS-block offset; a link-time VA-shaped value is invalid. */
    memcpy(mutated, source, source_size);
    write_u64(mutated + symbol_value_offset, tls_address);
    int accepted = expect_status(mutated, source_size, URP_STATUS_UNSUPPORTED, "absolute-VA STT_TLS value");

    /* The symbol extent itself must fit within PT_TLS, not merely its start. */
    if (accepted && symbol_size <= tls_size) {
        memcpy(mutated, source, source_size);
        write_u64(mutated + symbol_value_offset, tls_size - symbol_size + 1U);
        accepted = expect_status(mutated, source_size, URP_STATUS_UNSUPPORTED, "STT_TLS extent beyond PT_TLS");
    }
    if (accepted) {
        (void)printf("TLS symbol bounds (%u): PASS\n", relocation_type);
    }
    free(mutated);
    free(source);
    return accepted;
}

static int test_tls_module_id_requires_pt_tls(const char *path)
{
    uint8_t *source = NULL;
    uint8_t *mutated = NULL;
    size_t source_size = 0U;
    uint64_t phoff;
    uint16_t phnum;
    struct dynamic_facts facts;
    uint64_t tls_address = 0U;
    uint64_t tls_size = 0U;
    size_t symbol_value_offset;
    uint64_t symbol_size;
    size_t tls_header_offset = SIZE_MAX;
    if (!read_file(path, &source, &source_size)
        || !program_header_table(source, source_size, &phoff, &phnum)
        || !find_dynamic_facts(source, source_size, &facts)
        || !find_tls_layout(source, source_size, phoff, phnum, &tls_address, &tls_size)
        || !find_tls_symbol_record(
            source, source_size, &facts, phoff, phnum, R_AARCH64_TLS_DTPMOD64,
            &symbol_value_offset, &symbol_size)
        || !expect_status(source, source_size, URP_STATUS_OK, "positive TLS module-id")) {
        free(source);
        (void)fputs("TLS module-id fixture is malformed or did not pass\n", stderr);
        return 0;
    }
    (void)tls_address;
    (void)tls_size;
    (void)symbol_value_offset;
    (void)symbol_size;

    for (uint16_t index = 0U; index < phnum; ++index) {
        size_t header_offset = (size_t)(phoff + (uint64_t)index * PROGRAM_HEADER_SIZE);
        if (read_u32(source + header_offset) == PT_TLS) {
            tls_header_offset = header_offset;
            break;
        }
    }
    if (tls_header_offset == SIZE_MAX) {
        free(source);
        return 0;
    }
    mutated = (uint8_t *)malloc(source_size);
    if (mutated == NULL) {
        free(source);
        return 0;
    }
    memcpy(mutated, source, source_size);
    write_u32(mutated + tls_header_offset, 0U);
    int accepted = expect_status(
        mutated, source_size, URP_STATUS_UNSUPPORTED, "TLS module-id without PT_TLS");
    if (accepted) {
        (void)puts("TLS module-id PT_TLS requirement: PASS");
    }
    free(mutated);
    free(source);
    return accepted;
}

static int find_string_offset(
    const uint8_t *image,
    size_t image_size,
    uint64_t phoff,
    uint16_t phnum,
    const struct dynamic_facts *facts,
    const char *wanted,
    uint32_t *offset_out)
{
    if (facts->strsz == 0U || facts->strsz > SIZE_MAX) {
        return 0;
    }
    size_t string_table_offset;
    if (!map_virtual_range(
            image, image_size, phoff, phnum,
            facts->strtab_address, facts->strsz, &string_table_offset)) {
        return 0;
    }
    size_t string_size = (size_t)facts->strsz;
    size_t wanted_length = strlen(wanted);
    for (size_t offset = 0U; offset < string_size;) {
        const char *value = (const char *)(image + string_table_offset + offset);
        size_t remaining = string_size - offset;
        const char *terminator = (const char *)memchr(value, 0, remaining);
        if (terminator == NULL) {
            return 0;
        }
        size_t length = (size_t)(terminator - value);
        if (length == wanted_length && memcmp(value, wanted, length) == 0) {
            if (offset > UINT32_MAX) {
                return 0;
            }
            *offset_out = (uint32_t)offset;
            return 1;
        }
        offset += length + 1U;
    }
    return 0;
}

static int test_loader_version_file_pair(const char *path)
{
    uint8_t *source = NULL;
    uint8_t *mutated = NULL;
    size_t source_size = 0U;
    uint64_t phoff;
    uint16_t phnum;
    struct dynamic_facts facts;
    if (!read_file(path, &source, &source_size)
        || !program_header_table(source, source_size, &phoff, &phnum)
        || !find_dynamic_facts(source, source_size, &facts)
        || facts.needed_count != 2U
        || facts.verneed_address == 0U) {
        free(source);
        (void)fputs("TLS loader-version fixture is malformed or lacks the exact dependency pair\n", stderr);
        return 0;
    }

    size_t verneed_offset;
    if (!map_virtual_range(source, source_size, phoff, phnum, facts.verneed_address, 16U, &verneed_offset)) {
        free(source);
        return 0;
    }
    uint32_t loader_file_offset = read_u32(source + verneed_offset + 4U);
    uint32_t resolver_string_offset;
    if (!find_string_offset(
            source, source_size, phoff, phnum, &facts,
            "__tls_get_addr", &resolver_string_offset)) {
        free(source);
        (void)fputs("TLS loader-version fixture lacks the bounded resolver string\n", stderr);
        return 0;
    }

    size_t string_table_offset;
    if (!map_virtual_range(
            source, source_size, phoff, phnum,
            facts.strtab_address, facts.strsz, &string_table_offset)
        || loader_file_offset >= facts.strsz) {
        free(source);
        (void)fputs("TLS pair fixture does not carry a bounded loader vn_file\n", stderr);
        return 0;
    }
    static const char loader_name[] = "ld-linux-aarch64.so.1";
    uint64_t loader_name_bytes = (uint64_t)sizeof(loader_name);
    if (loader_name_bytes > facts.strsz - loader_file_offset
        || memcmp(
            source + string_table_offset + (size_t)loader_file_offset,
            loader_name,
            sizeof(loader_name)) != 0) {
        free(source);
        (void)fputs("TLS pair fixture does not carry the expected loader vn_file\n", stderr);
        return 0;
    }

    if (!expect_status(source, source_size, URP_STATUS_OK, "exact glibc pair loader vn_file")) {
        free(source);
        return 0;
    }
    mutated = (uint8_t *)malloc(source_size);
    if (mutated == NULL) {
        free(source);
        return 0;
    }

    /* A version filename must be one of the exact DT_NEEDED names, not any dynstr string. */
    memcpy(mutated, source, source_size);
    write_u32(mutated + verneed_offset + 4U, resolver_string_offset);
    int accepted = expect_status(mutated, source_size, URP_STATUS_UNSUPPORTED, "non-dependency vn_file");

    /* The loader vn_file is admitted only while the exact libc+loader pair is present. */
    if (accepted) {
        memcpy(mutated, source, source_size);
        write_u64(mutated + facts.needed_value_offsets[1], facts.needed_name_offsets[0]);
        accepted = expect_status(mutated, source_size, URP_STATUS_UNSUPPORTED, "duplicate libc dependency with loader vn_file");
    }
    if (accepted) {
        (void)puts("TLS loader-version/dependency boundary: PASS");
    }
    free(mutated);
    free(source);
    return accepted;
}

int main(int argc, char **argv)
{
    if (argc != 5
        || !test_tls_symbol_bounds(argv[1], R_AARCH64_TLS_TPREL64)
        || !test_tls_symbol_bounds(argv[2], R_AARCH64_TLS_DTPMOD64)
        || !test_tls_symbol_bounds(argv[2], R_AARCH64_TLS_DTPREL64)
        || !test_tls_symbol_bounds(argv[3], R_AARCH64_TLSDESC)
        || !test_tls_module_id_requires_pt_tls(argv[2])
        || !test_loader_version_file_pair(argv[4])) {
        return 1;
    }
    return 0;
}
