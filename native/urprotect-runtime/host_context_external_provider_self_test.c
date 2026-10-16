#define _GNU_SOURCE

#include "host_image_validation.h"
#include "sha256.h"
#include "urp/host_adapter.h"

#include <dlfcn.h>
#include <errno.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TEST_ELF_HEADER_SIZE 64U
#define TEST_PROGRAM_HEADER_SIZE 56U
#define TEST_DYNAMIC_ENTRY_SIZE 16U
#define TEST_SYMBOL_SIZE 24U
#define TEST_RELA_SIZE 24U
#define TEST_PT_LOAD 1U
#define TEST_PT_DYNAMIC 2U
#define TEST_PT_NOTE 4U
#define TEST_PF_W 2U
#define TEST_PF_X 1U
#define TEST_DT_NEEDED 1U
#define TEST_DT_STRTAB 5U
#define TEST_DT_STRSZ 10U
#define TEST_DYN_TAG_IGNORED UINT64_C(0x6ffffef0)
#define TEST_DT_GNU_HASH UINT64_C(0x6ffffef5)
#define TEST_DT_VERSYM UINT64_C(0x6ffffff0)
#define TEST_DT_VERDEF UINT64_C(0x6ffffffc)
#define TEST_DT_VERDEFNUM UINT64_C(0x6ffffffd)
#define TEST_DT_VERNEED UINT64_C(0x6ffffffe)
#define TEST_DT_VERNEEDNUM UINT64_C(0x6fffffff)
#define TEST_DT_SYMTAB 6U
#define TEST_DT_RELA 7U
#define TEST_DT_RELASZ 8U
#define TEST_DT_RELAENT 9U
#define TEST_DT_SYMENT 11U
#define TEST_R_AARCH64_GLOB_DAT 1025U
#define TEST_STB_GLOBAL 1U
#define TEST_STT_OBJECT 1U
#define TEST_SHN_UNDEF 0U
#define TEST_MAX_FILE_SIZE (64U * 1024U * 1024U)
#define TEST_CAPTURE_LIMIT 1024U
#define TEST_PROVIDER_AGGREGATE_WORK_BUDGET (UINT64_C(8) * 1024U * 1024U)

static uint16_t read_u16(const uint8_t *bytes)
{
    return (uint16_t)bytes[0] | (uint16_t)((uint16_t)bytes[1] << 8U);
}

static uint32_t read_u32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8U)
        | ((uint32_t)bytes[2] << 16U) | ((uint32_t)bytes[3] << 24U);
}

static uint64_t read_u64(const uint8_t *bytes)
{
    uint64_t value = 0U;
    for (size_t index = 0U; index < 8U; ++index) {
        value |= (uint64_t)bytes[index] << (index * 8U);
    }
    return value;
}

static void write_u64(uint8_t *bytes, uint64_t value)
{
    for (size_t index = 0U; index < 8U; ++index) {
        bytes[index] = (uint8_t)(value >> (index * 8U));
    }
}

static int range_valid(size_t size, uint64_t offset, uint64_t length)
{
    return offset <= (uint64_t)size && length <= (uint64_t)size - offset;
}

static int read_file(const char *path, uint8_t **bytes_out, size_t *size_out)
{
    if (path == NULL || bytes_out == NULL || size_out == NULL) return 0;
    *bytes_out = NULL;
    *size_out = 0U;
    FILE *file = fopen(path, "rb");
    if (file == NULL || fseek(file, 0L, SEEK_END) != 0) {
        if (file != NULL) (void)fclose(file);
        return 0;
    }
    long length = ftell(file);
    if (length <= 0L || (uint64_t)length > (uint64_t)TEST_MAX_FILE_SIZE
        || fseek(file, 0L, SEEK_SET) != 0) {
        (void)fclose(file);
        return 0;
    }
    size_t size = (size_t)length;
    uint8_t *bytes = (uint8_t *)malloc(size);
    if (bytes == NULL || fread(bytes, 1U, size, file) != size || ferror(file) != 0) {
        free(bytes);
        (void)fclose(file);
        return 0;
    }
    if (fclose(file) != 0) {
        free(bytes);
        return 0;
    }
    *bytes_out = bytes;
    *size_out = size;
    return 1;
}

static void digest_hex(const uint8_t *bytes, size_t size, char output[65])
{
    static const char hex[] = "0123456789abcdef";
    uint8_t digest[32];
    urp_sha256_context context;
    urp_sha256_init(&context);
    urp_sha256_update(&context, bytes, size);
    urp_sha256_final(&context, digest);
    for (size_t index = 0U; index < sizeof(digest); ++index) {
        output[index * 2U] = hex[digest[index] >> 4U];
        output[(index * 2U) + 1U] = hex[digest[index] & 0x0fU];
    }
    output[64] = '\0';
}

static void bytes_hex(const uint8_t *bytes, size_t size, char *output)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t index = 0U; index < size; ++index) {
        output[index * 2U] = hex[bytes[index] >> 4U];
        output[(index * 2U) + 1U] = hex[bytes[index] & 0x0fU];
    }
    output[size * 2U] = '\0';
}

static int provider_build_id(
    const uint8_t *image,
    size_t image_size,
    char output[URP_HOST_PROVIDER_BUILD_ID_HEX_CAPACITY])
{
    if (image_size < TEST_ELF_HEADER_SIZE) return 0;
    uint64_t phoff = read_u64(image + 32U);
    uint16_t phnum = read_u16(image + 56U);
    uint64_t phbytes = (uint64_t)phnum * TEST_PROGRAM_HEADER_SIZE;
    if (phnum == 0U || !range_valid(image_size, phoff, phbytes)) return 0;
    uint8_t build_id[20];
    int found = 0;
    for (uint16_t index = 0U; index < phnum; ++index) {
        const uint8_t *ph = image + (size_t)phoff + (size_t)index * TEST_PROGRAM_HEADER_SIZE;
        if (read_u32(ph) != TEST_PT_NOTE) continue;
        uint64_t note_offset = read_u64(ph + 8U);
        uint64_t note_size = read_u64(ph + 32U);
        if (!range_valid(image_size, note_offset, note_size)) return 0;
        uint64_t cursor = 0U;
        while (cursor < note_size) {
            if (note_size - cursor < 12U) return 0;
            const uint8_t *note = image + (size_t)(note_offset + cursor);
            uint32_t namesz = read_u32(note);
            uint32_t descsz = read_u32(note + 4U);
            uint32_t type = read_u32(note + 8U);
            uint64_t name_padded = ((uint64_t)namesz + 3U) & ~UINT64_C(3);
            uint64_t desc_padded = ((uint64_t)descsz + 3U) & ~UINT64_C(3);
            uint64_t record_size = 12U + name_padded + desc_padded;
            if (record_size > note_size - cursor) return 0;
            if (namesz == 4U && type == 3U && memcmp(note + 12U, "GNU\0", 4U) == 0) {
                if (found || descsz != sizeof(build_id)) return 0;
                memcpy(build_id, note + 12U + (size_t)name_padded, sizeof(build_id));
                found = 1;
            }
            cursor += record_size;
        }
    }
    if (!found) return 0;
    bytes_hex(build_id, sizeof(build_id), output);
    return 1;
}

static int identify_provider(
    const char *path,
    char build_id[URP_HOST_PROVIDER_BUILD_ID_HEX_CAPACITY],
    char sha256[URP_HOST_PROVIDER_SHA256_HEX_CAPACITY])
{
    uint8_t *bytes = NULL;
    size_t size = 0U;
    if (!read_file(path, &bytes, &size)) return 0;
    int result = provider_build_id(bytes, size, build_id);
    if (result) digest_hex(bytes, size, sha256);
    free(bytes);
    return result;
}

static int virtual_to_file(
    const uint8_t *image,
    size_t image_size,
    uint64_t phoff,
    uint16_t phnum,
    uint64_t address,
    uint64_t length,
    size_t *file_offset_out)
{
    size_t matches = 0U;
    size_t resolved = 0U;
    for (uint16_t index = 0U; index < phnum; ++index) {
        const uint8_t *ph = image + (size_t)phoff + (size_t)index * TEST_PROGRAM_HEADER_SIZE;
        if (read_u32(ph) != TEST_PT_LOAD) continue;
        uint64_t vaddr = read_u64(ph + 16U);
        uint64_t filesz = read_u64(ph + 32U);
        if (address < vaddr) continue;
        uint64_t delta = address - vaddr;
        if (delta > filesz || length > filesz - delta) continue;
        uint64_t file_offset = read_u64(ph + 8U) + delta;
        if (!range_valid(image_size, file_offset, length)) return 0;
        resolved = (size_t)file_offset;
        ++matches;
    }
    if (matches != 1U) return 0;
    *file_offset_out = resolved;
    return 1;
}

typedef struct provider_relocation_facts {
    uint64_t got_virtual_address;
    uint32_t relocation_type;
    uint64_t addend;
    uint64_t symbol_size;
} provider_relocation_facts;

static int consumer_provider_relocation(
    const uint8_t *image,
    size_t image_size,
    provider_relocation_facts *facts)
{
    if (image_size < TEST_ELF_HEADER_SIZE || facts == NULL) return 0;
    uint64_t phoff = read_u64(image + 32U);
    uint16_t phnum = read_u16(image + 56U);
    if (phnum == 0U || !range_valid(image_size, phoff,
            (uint64_t)phnum * TEST_PROGRAM_HEADER_SIZE)) return 0;
    uint64_t dynamic_offset = 0U;
    uint64_t dynamic_size = 0U;
    size_t dynamic_count = 0U;
    for (uint16_t index = 0U; index < phnum; ++index) {
        const uint8_t *ph = image + (size_t)phoff + (size_t)index * TEST_PROGRAM_HEADER_SIZE;
        if (read_u32(ph) != TEST_PT_DYNAMIC) continue;
        dynamic_offset = read_u64(ph + 8U);
        dynamic_size = read_u64(ph + 32U);
        ++dynamic_count;
    }
    if (dynamic_count != 1U || dynamic_size % TEST_DYNAMIC_ENTRY_SIZE != 0U
        || !range_valid(image_size, dynamic_offset, dynamic_size)) return 0;
    uint64_t strtab = 0U, strsz = 0U, symtab = 0U, syment = 0U;
    uint64_t rela = 0U, relasz = 0U, relaent = 0U;
    int has_strtab = 0, has_strsz = 0, has_symtab = 0, has_syment = 0;
    int has_rela = 0, has_relasz = 0, has_relaent = 0, terminated = 0;
    for (uint64_t offset = 0U; offset < dynamic_size; offset += TEST_DYNAMIC_ENTRY_SIZE) {
        const uint8_t *entry = image + (size_t)(dynamic_offset + offset);
        uint64_t tag = read_u64(entry);
        uint64_t value = read_u64(entry + 8U);
        if (tag == 0U) {
            terminated = 1;
            break;
        }
        switch (tag) {
        case TEST_DT_STRTAB: if (has_strtab) return 0; strtab = value; has_strtab = 1; break;
        case TEST_DT_STRSZ: if (has_strsz) return 0; strsz = value; has_strsz = 1; break;
        case TEST_DT_SYMTAB: if (has_symtab) return 0; symtab = value; has_symtab = 1; break;
        case TEST_DT_SYMENT: if (has_syment) return 0; syment = value; has_syment = 1; break;
        case TEST_DT_RELA: if (has_rela) return 0; rela = value; has_rela = 1; break;
        case TEST_DT_RELASZ: if (has_relasz) return 0; relasz = value; has_relasz = 1; break;
        case TEST_DT_RELAENT: if (has_relaent) return 0; relaent = value; has_relaent = 1; break;
        case TEST_DT_NEEDED: break;
        default: break;
        }
    }
    if (!terminated || !has_strtab || !has_strsz || !has_symtab || !has_syment
        || !has_rela || !has_relasz || !has_relaent || syment != TEST_SYMBOL_SIZE
        || relaent != TEST_RELA_SIZE || relasz != TEST_RELA_SIZE) return 0;
    size_t rela_file_offset;
    if (!virtual_to_file(image, image_size, phoff, phnum, rela, relasz, &rela_file_offset)) return 0;
    const uint8_t *row = image + rela_file_offset;
    uint64_t info = read_u64(row + 8U);
    uint64_t symbol_index = info >> 32U;
    facts->relocation_type = (uint32_t)info;
    facts->got_virtual_address = read_u64(row);
    facts->addend = read_u64(row + 16U);
    if (facts->relocation_type != TEST_R_AARCH64_GLOB_DAT || symbol_index == 0U
        || facts->addend != 0U) return 0;
    uint64_t symbol_address = symtab + symbol_index * syment;
    size_t symbol_file_offset;
    size_t strings_file_offset;
    if (!virtual_to_file(image, image_size, phoff, phnum, symbol_address, syment, &symbol_file_offset)
        || !virtual_to_file(image, image_size, phoff, phnum, strtab, strsz, &strings_file_offset)) return 0;
    const uint8_t *symbol = image + symbol_file_offset;
    uint32_t name_offset = read_u32(symbol);
    uint8_t info_byte = symbol[4U];
    uint8_t other = symbol[5U];
    uint16_t shndx = read_u16(symbol + 6U);
    facts->symbol_size = read_u64(symbol + 16U);
    if (name_offset >= strsz || (facts->symbol_size != 0U && facts->symbol_size != 16U)
        || (info_byte >> 4U) != TEST_STB_GLOBAL || (info_byte & 0x0fU) != TEST_STT_OBJECT
        || other != 0U || shndx != TEST_SHN_UNDEF
        || strnlen((const char *)(image + strings_file_offset + name_offset), (size_t)(strsz - name_offset))
            != sizeof(URP_HOST_EXTERNAL_TABLE_SYMBOL) - 1U
        || memcmp(image + strings_file_offset + name_offset,
            URP_HOST_EXTERNAL_TABLE_SYMBOL, sizeof(URP_HOST_EXTERNAL_TABLE_SYMBOL)) != 0) return 0;
    return 1;
}

static int consumer_with_version_tag(
    const uint8_t *source,
    size_t source_size,
    uint64_t version_tag,
    uint8_t **mutated_out,
    size_t *mutated_size_out)
{
    if (source == NULL || mutated_out == NULL || mutated_size_out == NULL
        || source_size < TEST_ELF_HEADER_SIZE) return 0;
    *mutated_out = NULL;
    *mutated_size_out = 0U;
    uint64_t phoff = read_u64(source + 32U);
    uint16_t phnum = read_u16(source + 56U);
    if (phnum == 0U || phnum > 4096U
        || !range_valid(source_size, phoff, (uint64_t)phnum * TEST_PROGRAM_HEADER_SIZE)) return 0;

    uint64_t dynamic_offset = 0U;
    uint64_t dynamic_size = 0U;
    size_t dynamic_segments = 0U;
    for (uint16_t index = 0U; index < phnum; ++index) {
        const uint8_t *header = source + (size_t)phoff
            + (size_t)index * TEST_PROGRAM_HEADER_SIZE;
        if (read_u32(header) != TEST_PT_DYNAMIC) continue;
        dynamic_offset = read_u64(header + 8U);
        dynamic_size = read_u64(header + 32U);
        ++dynamic_segments;
    }
    if (dynamic_segments != 1U || dynamic_size == 0U
        || dynamic_size % TEST_DYNAMIC_ENTRY_SIZE != 0U
        || !range_valid(source_size, dynamic_offset, dynamic_size)) return 0;

    uint64_t gnu_hash_entry_offset = 0U;
    size_t gnu_hash_count = 0U;
    int terminated = 0;
    for (uint64_t cursor = 0U; cursor < dynamic_size; cursor += TEST_DYNAMIC_ENTRY_SIZE) {
        uint64_t entry_offset = dynamic_offset + cursor;
        const uint8_t *entry = source + (size_t)entry_offset;
        uint64_t tag = read_u64(entry);
        if (tag == 0U) {
            terminated = 1;
            break;
        }
        if (tag == TEST_DT_GNU_HASH) {
            gnu_hash_entry_offset = entry_offset;
            ++gnu_hash_count;
        }
    }
    if (!terminated || gnu_hash_count != 1U) return 0;

    uint8_t *mutated = (uint8_t *)malloc(source_size);
    if (mutated == NULL) return 0;
    memcpy(mutated, source, source_size);
    write_u64(mutated + (size_t)gnu_hash_entry_offset, version_tag);
    *mutated_out = mutated;
    *mutated_size_out = source_size;
    return 1;
}

static int consumer_without_provider_needed(
    const uint8_t *source,
    size_t source_size,
    uint8_t **mutated_out,
    size_t *mutated_size_out)
{
    if (source == NULL || mutated_out == NULL || mutated_size_out == NULL
        || source_size < TEST_ELF_HEADER_SIZE) return 0;
    *mutated_out = NULL;
    *mutated_size_out = 0U;
    uint64_t phoff = read_u64(source + 32U);
    uint16_t phnum = read_u16(source + 56U);
    if (phnum == 0U || phnum > 4096U
        || !range_valid(source_size, phoff, (uint64_t)phnum * TEST_PROGRAM_HEADER_SIZE)) return 0;
    uint64_t dynamic_offset = 0U;
    uint64_t dynamic_size = 0U;
    size_t dynamic_segments = 0U;
    for (uint16_t index = 0U; index < phnum; ++index) {
        const uint8_t *header = source + (size_t)phoff + (size_t)index * TEST_PROGRAM_HEADER_SIZE;
        if (read_u32(header) != TEST_PT_DYNAMIC) continue;
        dynamic_offset = read_u64(header + 8U);
        dynamic_size = read_u64(header + 32U);
        ++dynamic_segments;
    }
    if (dynamic_segments != 1U || dynamic_size % TEST_DYNAMIC_ENTRY_SIZE != 0U
        || !range_valid(source_size, dynamic_offset, dynamic_size)) return 0;

    uint64_t needed_offset = 0U;
    uint64_t string_table = 0U;
    uint64_t string_table_size = 0U;
    size_t needed_count = 0U;
    int have_strtab = 0;
    int have_strsz = 0;
    int terminated = 0;
    for (uint64_t cursor = 0U; cursor < dynamic_size; cursor += TEST_DYNAMIC_ENTRY_SIZE) {
        const uint8_t *entry = source + (size_t)(dynamic_offset + cursor);
        uint64_t tag = read_u64(entry);
        uint64_t value = read_u64(entry + 8U);
        if (tag == 0U) {
            terminated = 1;
            break;
        }
        if (tag == TEST_DT_NEEDED) {
            ++needed_count;
            needed_offset = value;
        } else if (tag == TEST_DT_STRTAB) {
            if (have_strtab) return 0;
            string_table = value;
            have_strtab = 1;
        } else if (tag == TEST_DT_STRSZ) {
            if (have_strsz) return 0;
            string_table_size = value;
            have_strsz = 1;
        }
    }
    size_t string_file_offset;
    if (!terminated || needed_count != 1U || !have_strtab || !have_strsz
        || string_table_size == 0U || needed_offset >= string_table_size
        || !virtual_to_file(source, source_size, phoff, phnum,
            string_table, string_table_size, &string_file_offset)) return 0;
    const char *needed = (const char *)(source + string_file_offset + (size_t)needed_offset);
    size_t needed_remaining = (size_t)(string_table_size - needed_offset);
    if (strnlen(needed, needed_remaining) != strlen(URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME)
        || memcmp(needed, URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME,
            sizeof(URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME)) != 0) return 0;

    uint8_t *mutated = (uint8_t *)malloc(source_size);
    if (mutated == NULL) return 0;
    memcpy(mutated, source, source_size);
    for (uint64_t cursor = 0U; cursor < dynamic_size; cursor += TEST_DYNAMIC_ENTRY_SIZE) {
        uint8_t *entry = mutated + (size_t)(dynamic_offset + cursor);
        if (read_u64(entry) == TEST_DT_NEEDED) {
            write_u64(entry, TEST_DYN_TAG_IGNORED);
            *mutated_out = mutated;
            *mutated_size_out = source_size;
            return 1;
        }
        if (read_u64(entry) == 0U) break;
    }
    free(mutated);
    return 0;
}

static size_t maximum_accepted_needed_length(void)
{
    static const char *const accepted[] = {
        URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME,
        "libc.so.6",
        "ld-linux-aarch64.so.1",
        "libc.so",
        "libc.musl-aarch64.so.1",
        "libc.so.1",
    };
    size_t maximum = 0U;
    for (size_t index = 0U; index < sizeof(accepted) / sizeof(accepted[0]); ++index) {
        size_t length = strlen(accepted[index]);
        if (length > maximum) maximum = length;
    }
    return maximum;
}

static int consumer_with_long_needed_name(
    const uint8_t *source,
    size_t source_size,
    uint8_t **mutated_out,
    size_t *mutated_size_out)
{
    if (source == NULL || mutated_out == NULL || mutated_size_out == NULL
        || source_size < TEST_ELF_HEADER_SIZE) return 0;
    *mutated_out = NULL;
    *mutated_size_out = 0U;
    uint64_t phoff = read_u64(source + 32U);
    uint16_t phnum = read_u16(source + 56U);
    if (phnum == 0U || phnum > 4096U
        || !range_valid(source_size, phoff, (uint64_t)phnum * TEST_PROGRAM_HEADER_SIZE)) return 0;
    uint64_t dynamic_offset = 0U;
    uint64_t dynamic_size = 0U;
    size_t dynamic_segments = 0U;
    for (uint16_t index = 0U; index < phnum; ++index) {
        const uint8_t *header = source + (size_t)phoff
            + (size_t)index * TEST_PROGRAM_HEADER_SIZE;
        if (read_u32(header) != TEST_PT_DYNAMIC) continue;
        dynamic_offset = read_u64(header + 8U);
        dynamic_size = read_u64(header + 32U);
        ++dynamic_segments;
    }
    if (dynamic_segments != 1U || dynamic_size == 0U
        || dynamic_size % TEST_DYNAMIC_ENTRY_SIZE != 0U
        || !range_valid(source_size, dynamic_offset, dynamic_size)) return 0;

    uint64_t needed_offset = 0U;
    uint64_t string_table = 0U;
    uint64_t string_table_size = 0U;
    size_t needed_count = 0U;
    int have_strtab = 0;
    int have_strsz = 0;
    int terminated = 0;
    for (uint64_t cursor = 0U; cursor < dynamic_size; cursor += TEST_DYNAMIC_ENTRY_SIZE) {
        const uint8_t *entry = source + (size_t)(dynamic_offset + cursor);
        uint64_t tag = read_u64(entry);
        uint64_t value = read_u64(entry + 8U);
        if (tag == 0U) {
            terminated = 1;
            break;
        }
        if (tag == TEST_DT_NEEDED) {
            ++needed_count;
            needed_offset = value;
        } else if (tag == TEST_DT_STRTAB) {
            if (have_strtab) return 0;
            string_table = value;
            have_strtab = 1;
        } else if (tag == TEST_DT_STRSZ) {
            if (have_strsz) return 0;
            string_table_size = value;
            have_strsz = 1;
        }
    }
    size_t string_file_offset;
    size_t maximum_length = maximum_accepted_needed_length();
    if (!terminated || needed_count != 1U || !have_strtab || !have_strsz
        || string_table_size == 0U || needed_offset >= string_table_size
        || string_table_size - needed_offset < (uint64_t)(maximum_length + 1U)
        || !virtual_to_file(source, source_size, phoff, phnum,
            string_table, string_table_size, &string_file_offset)) return 0;

    uint8_t *mutated = (uint8_t *)malloc(source_size);
    if (mutated == NULL) return 0;
    memcpy(mutated, source, source_size);
    size_t needed_file_offset = string_file_offset + (size_t)needed_offset;
    memset(mutated + needed_file_offset, 'x', maximum_length + 1U);
    *mutated_out = mutated;
    *mutated_size_out = source_size;
    return 1;
}

static int expect_rejected_with_status(
    urp_host_adapter_v1 *adapter,
    const uint8_t *consumer,
    size_t consumer_size,
    urp_status expected_status)
{
    size_t attempts_before = urp_host_adapter_memfd_create_attempts();
    size_t loaders_before = urp_host_adapter_loader_attempts();
    urp_image_handle handle = UINT64_C(0xfeedface);
    urp_status status = adapter->context.load_image(
        adapter->context.userdata, consumer, consumer_size,
        URP_LOAD_IMAGE_IMMUTABLE, &handle);
    size_t attempts_after = urp_host_adapter_memfd_create_attempts();
    size_t loaders_after = urp_host_adapter_loader_attempts();
    if (status != expected_status || handle != 0U || attempts_after != attempts_before
        || loaders_after != loaders_before) {
        (void)fprintf(stderr, "negative rejected load status=%d expected=%d handle=%llu memfd=%zu->%zu loader=%zu->%zu\n",
            (int)status, (int)expected_status, (unsigned long long)handle,
            attempts_before, attempts_after, loaders_before, loaders_after);
        return 0;
    }
    return 1;
}

static int expect_rejected(
    urp_host_adapter_v1 *adapter,
    const uint8_t *consumer,
    size_t consumer_size)
{
    return expect_rejected_with_status(
        adapter, consumer, consumer_size, URP_STATUS_UNSUPPORTED);
}

static int configured_adapter(
    urp_host_adapter_v1 *adapter,
    const char *provider_path,
    const char *soname,
    const char *build_id,
    const char *sha256)
{
    urp_host_provider_config_v1 config = {
        .path = provider_path,
        .expected_soname = soname,
        .expected_build_id_hex = build_id,
        .expected_sha256_hex = sha256,
    };
    return urp_host_adapter_init_with_provider(adapter, &config) == URP_STATUS_OK;
}

static int capture_dispatch(
    urp_entry_fn entry,
    urp_entry_fn observer,
    const urp_host_context_v1 *host,
    uint32_t index,
    int32_t *entry_status,
    int32_t *observer_status,
    uint8_t stdout_bytes[TEST_CAPTURE_LIMIT],
    size_t *stdout_size,
    uint8_t stderr_bytes[TEST_CAPTURE_LIMIT],
    size_t *stderr_size)
{
    FILE *stdout_file = tmpfile();
    FILE *stderr_file = tmpfile();
    if (stdout_file == NULL || stderr_file == NULL) {
        if (stdout_file != NULL) (void)fclose(stdout_file);
        if (stderr_file != NULL) (void)fclose(stderr_file);
        return 0;
    }
    int saved_stdout = dup(STDOUT_FILENO);
    int saved_stderr = dup(STDERR_FILENO);
    if (saved_stdout < 0 || saved_stderr < 0
        || dup2(fileno(stdout_file), STDOUT_FILENO) < 0
        || dup2(fileno(stderr_file), STDERR_FILENO) < 0) {
        if (saved_stdout >= 0) (void)close(saved_stdout);
        if (saved_stderr >= 0) (void)close(saved_stderr);
        (void)fclose(stdout_file);
        (void)fclose(stderr_file);
        return 0;
    }

    const char *const argv[] = { "external-provider-fixture", NULL };
    urp_launch_args_v1 args = {
        .abi_version = URP_HOST_ABI_VERSION,
        .struct_size = sizeof(urp_launch_args_v1),
        .argc = index,
        .argv = argv,
        .envp = NULL,
        .image = 0U,
    };
    *entry_status = entry(host, &args);
    *observer_status = observer(host, &args);
    (void)fflush(NULL);
    int restore_status = dup2(saved_stdout, STDOUT_FILENO) < 0
        || dup2(saved_stderr, STDERR_FILENO) < 0;
    (void)close(saved_stdout);
    (void)close(saved_stderr);
    if (restore_status || fseek(stdout_file, 0L, SEEK_END) != 0
        || fseek(stderr_file, 0L, SEEK_END) != 0) {
        (void)fclose(stdout_file);
        (void)fclose(stderr_file);
        return 0;
    }
    long stdout_length = ftell(stdout_file);
    long stderr_length = ftell(stderr_file);
    if (stdout_length < 0L || stderr_length < 0L
        || (uint64_t)stdout_length > TEST_CAPTURE_LIMIT
        || (uint64_t)stderr_length > TEST_CAPTURE_LIMIT
        || fseek(stdout_file, 0L, SEEK_SET) != 0
        || fseek(stderr_file, 0L, SEEK_SET) != 0) {
        (void)fclose(stdout_file);
        (void)fclose(stderr_file);
        return 0;
    }
    *stdout_size = (size_t)stdout_length;
    *stderr_size = (size_t)stderr_length;
    int read_ok = fread(stdout_bytes, 1U, *stdout_size, stdout_file) == *stdout_size
        && fread(stderr_bytes, 1U, *stderr_size, stderr_file) == *stderr_size;
    int close_ok = fclose(stdout_file) == 0 && fclose(stderr_file) == 0;
    return read_ok && close_ok;
}

static int address_mapping(
    uintptr_t address,
    char permissions_out[5],
    char *line_out,
    size_t line_capacity)
{
    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps == NULL) return 0;
    char line[4096];
    int found = 0;
    while (fgets(line, (int)sizeof(line), maps) != NULL) {
        unsigned long long start;
        unsigned long long end;
        char permissions[5] = {0};
        unsigned long long offset;
        unsigned int device_major;
        unsigned int device_minor;
        unsigned long long inode;
        int fields = sscanf(line, "%llx-%llx %4s %llx %x:%x %llu",
            &start, &end, permissions, &offset, &device_major, &device_minor, &inode);
        (void)offset;
        (void)device_major;
        (void)device_minor;
        (void)inode;
        if (fields != 7 || address < (uintptr_t)start || address >= (uintptr_t)end) continue;
        memcpy(permissions_out, permissions, sizeof(permissions));
        if (line_out != NULL && line_capacity != 0U) {
            size_t length = strnlen(line, sizeof(line));
            if (length >= line_capacity) length = line_capacity - 1U;
            memcpy(line_out, line, length);
            line_out[length] = '\0';
        }
        found = 1;
        break;
    }
    if (fclose(maps) != 0) return 0;
    return found;
}

static int no_mapping_at(uintptr_t address)
{
    char permissions[5] = {0};
    return !address_mapping(address, permissions, NULL, 0U);
}

int main(int argc, char **argv)
{
    if (argc != 10) {
        (void)fprintf(stderr, "usage: %s provider consumer bad-size wrong-soname bad-dependencies conflict symbol-conflict wrong-consumer versioned-libc\n", argv[0]);
        return 2;
    }
    uint8_t *provider_bytes = NULL;
    uint8_t *consumer_bytes = NULL;
    uint8_t *bad_consumer_bytes = NULL;
    uint8_t *missing_dependency_bytes = NULL;
    uint8_t *versioned_libc_bytes = NULL;
    size_t versioned_libc_size = 0U;
    size_t provider_size = 0U;
    size_t consumer_size = 0U;
    size_t bad_consumer_size = 0U;
    size_t missing_dependency_size = 0U;
    char build_id[URP_HOST_PROVIDER_BUILD_ID_HEX_CAPACITY] = {0};
    char sha256[URP_HOST_PROVIDER_SHA256_HEX_CAPACITY] = {0};
    if (!read_file(argv[1], &provider_bytes, &provider_size)
        || !read_file(argv[2], &consumer_bytes, &consumer_size)
        || !read_file(argv[8], &bad_consumer_bytes, &bad_consumer_size)
        || !read_file(argv[9], &versioned_libc_bytes, &versioned_libc_size)
        || !consumer_without_provider_needed(
            consumer_bytes, consumer_size, &missing_dependency_bytes, &missing_dependency_size)
        || !identify_provider(argv[1], build_id, sha256)) {
        (void)fprintf(stderr, "provider fixture input read/identity failed\n");
        free(provider_bytes);
        free(consumer_bytes);
        free(bad_consumer_bytes);
        free(versioned_libc_bytes);
        return 1;
    }

    size_t dependency_count = 0U;
    int uses_provider = 0;
    uint64_t got_virtual_address = 0U;
    urp_status status = urp_host_image_validate_with_provider(
        consumer_bytes, consumer_size, URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME,
        &dependency_count, &uses_provider, &got_virtual_address);
    uint64_t exact_consumer_candidate_work =
        urp_host_image_validation_test_provider_candidate_work_used();
    uint64_t candidate_dynamic_entries =
        urp_host_image_validation_test_provider_candidate_dynamic_entries();
    uint64_t candidate_range_work =
        urp_host_image_validation_test_provider_candidate_range_work();
    uint64_t candidate_needed_string_bytes =
        urp_host_image_validation_test_provider_candidate_needed_string_bytes();
    uint64_t consumer_rela_validations =
        urp_host_image_validation_test_consumer_rela_validation_count();
    uint64_t symbol_version_validations =
        urp_host_image_validation_test_symbol_version_validation_count();
    provider_relocation_facts relocation = {0};
    provider_relocation_facts mutated_relocation = {0};
    urp_host_external_provider_facts provider_facts;
    int relocation_ok = consumer_provider_relocation(consumer_bytes, consumer_size, &relocation);
    int mutated_relocation_ok = consumer_provider_relocation(
        missing_dependency_bytes, missing_dependency_size, &mutated_relocation);
    if (status != URP_STATUS_OK || dependency_count != 1U || !uses_provider
        || got_virtual_address == 0U || exact_consumer_candidate_work == 0U
        || candidate_dynamic_entries == 0U || candidate_range_work == 0U
        || candidate_needed_string_bytes == 0U
        || consumer_rela_validations != 1U || symbol_version_validations != 1U
        || !relocation_ok || !mutated_relocation_ok
        || relocation.got_virtual_address != got_virtual_address
        || mutated_relocation.got_virtual_address != relocation.got_virtual_address
        || mutated_relocation.relocation_type != relocation.relocation_type
        || mutated_relocation.addend != relocation.addend
        || mutated_relocation.symbol_size != relocation.symbol_size) {
        (void)fprintf(stderr,
            "provider consumer candidate preflight did not reach its aggregate budgeted RELA check: status=%d dependencies=%zu uses=%d got=0x%llx work=%llu budgeted_calls=%llu relocation_ok=%d\n",
            (int)status, dependency_count, uses_provider,
            (unsigned long long)got_virtual_address,
            (unsigned long long)exact_consumer_candidate_work,
            (unsigned long long)consumer_rela_validations, relocation_ok);
        free(provider_bytes);
        free(consumer_bytes);
        free(bad_consumer_bytes);
        return 1;
    }

    static const uint64_t provider_version_tags[] = {
        TEST_DT_VERSYM,
        TEST_DT_VERNEED,
        TEST_DT_VERNEEDNUM,
        TEST_DT_VERDEF,
        TEST_DT_VERDEFNUM,
    };
    size_t versioned_dependency_count = 0U;
    int versioned_uses_provider = 1;
    uint64_t versioned_got_address = 1U;
    urp_status versioned_candidate_status = urp_host_image_validate_with_provider(
        versioned_libc_bytes, versioned_libc_size,
        URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME,
        &versioned_dependency_count, &versioned_uses_provider, &versioned_got_address);
    uint64_t versioned_candidate_work =
        urp_host_image_validation_test_provider_candidate_work_used();
    uint64_t versioned_candidate_version_calls =
        urp_host_image_validation_test_symbol_version_validation_count();
    uint64_t versioned_provider_parses_before =
        urp_host_image_validation_test_provider_parse_count();
    urp_host_adapter_v1 versioned_libc_adapter;
    urp_image_handle versioned_libc_handle = 0U;
    int versioned_libc_load_ok = configured_adapter(
            &versioned_libc_adapter, argv[1],
            URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME, build_id, sha256)
        && versioned_libc_adapter.context.load_image(
            versioned_libc_adapter.context.userdata,
            versioned_libc_bytes, versioned_libc_size,
            URP_LOAD_IMAGE_IMMUTABLE, &versioned_libc_handle) == URP_STATUS_OK
        && versioned_libc_handle != 0U;
    urp_status versioned_libc_release_status = URP_STATUS_OK;
    if (versioned_libc_handle != 0U) {
        versioned_libc_release_status = versioned_libc_adapter.context.release_image(
            versioned_libc_adapter.context.userdata, versioned_libc_handle);
    }
    if (versioned_candidate_status != URP_STATUS_OK
        || versioned_dependency_count != 1U || versioned_uses_provider
        || versioned_got_address != 0U || versioned_candidate_work == 0U
        || versioned_candidate_version_calls != 1U || !versioned_libc_load_ok
        || versioned_libc_release_status != URP_STATUS_OK
        || urp_host_image_validation_test_provider_parse_count()
            != versioned_provider_parses_before) {
        (void)fprintf(stderr,
            "configured provider mode regressed valid versioned libc image: preflight=%d dependencies=%zu provider=%d work=%llu version_calls=%llu load=%d release=%d provider_parses=%llu->%llu\n",
            (int)versioned_candidate_status, versioned_dependency_count,
            versioned_uses_provider, (unsigned long long)versioned_candidate_work,
            (unsigned long long)versioned_candidate_version_calls,
            versioned_libc_load_ok, (int)versioned_libc_release_status,
            (unsigned long long)versioned_provider_parses_before,
            (unsigned long long)urp_host_image_validation_test_provider_parse_count());
        return 1;
    }

    for (size_t tag_index = 0U;
        tag_index < sizeof(provider_version_tags) / sizeof(provider_version_tags[0]);
        ++tag_index) {
        uint8_t *versioned_consumer = NULL;
        size_t versioned_consumer_size = 0U;
        if (!consumer_with_version_tag(
                consumer_bytes, consumer_size, provider_version_tags[tag_index],
                &versioned_consumer, &versioned_consumer_size)) {
            (void)fprintf(stderr, "could not mutate provider consumer with version tag 0x%llx\n",
                (unsigned long long)provider_version_tags[tag_index]);
            return 1;
        }

        uint64_t provider_parse_count_before_version_tag =
            urp_host_image_validation_test_provider_parse_count();
        urp_host_adapter_v1 versioned_consumer_adapter;
        int version_tag_rejected = configured_adapter(
                &versioned_consumer_adapter, argv[1],
                URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME, build_id, sha256)
            && expect_rejected(
                &versioned_consumer_adapter, versioned_consumer, versioned_consumer_size);
        uint64_t version_tag_candidate_work =
            urp_host_image_validation_test_provider_candidate_work_used();
        uint64_t version_tag_rela_validations =
            urp_host_image_validation_test_consumer_rela_validation_count();
        uint64_t version_tag_version_validations =
            urp_host_image_validation_test_symbol_version_validation_count();
        uint64_t provider_parse_count_after_version_tag =
            urp_host_image_validation_test_provider_parse_count();
        free(versioned_consumer);
        if (!version_tag_rejected || version_tag_rela_validations != 0U || version_tag_version_validations != 0U
            || provider_parse_count_after_version_tag != provider_parse_count_before_version_tag) {
            (void)fprintf(stderr,
                "provider version tag 0x%llx was not rejected before version traversal/RELA/provider/memfd/loader work: rejected=%d candidate_work=%llu rela_calls=%llu version_calls=%llu provider_parses=%llu->%llu\n",
                (unsigned long long)provider_version_tags[tag_index], version_tag_rejected,
                (unsigned long long)version_tag_candidate_work,
                (unsigned long long)version_tag_rela_validations,
                (unsigned long long)version_tag_version_validations,
                (unsigned long long)provider_parse_count_before_version_tag,
                (unsigned long long)provider_parse_count_after_version_tag);
            return 1;
        }
    }

    uint8_t *long_needed_consumer = NULL;
    size_t long_needed_consumer_size = 0U;
    if (!consumer_with_long_needed_name(
            consumer_bytes, consumer_size,
            &long_needed_consumer, &long_needed_consumer_size)) {
        (void)fprintf(stderr, "could not construct long adversarial DT_NEEDED fixture\n");
        return 1;
    }
    uint64_t provider_parse_count_before_long_needed =
        urp_host_image_validation_test_provider_parse_count();
    urp_host_adapter_v1 long_needed_adapter;
    int long_needed_rejected = configured_adapter(
            &long_needed_adapter, argv[1],
            URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME, build_id, sha256)
        && expect_rejected(&long_needed_adapter, long_needed_consumer, long_needed_consumer_size);
    uint64_t long_needed_work =
        urp_host_image_validation_test_provider_candidate_work_used();
    uint64_t long_needed_bytes =
        urp_host_image_validation_test_provider_candidate_needed_string_bytes();
    uint64_t long_needed_rela_calls =
        urp_host_image_validation_test_consumer_rela_validation_count();
    uint64_t provider_parse_count_after_long_needed =
        urp_host_image_validation_test_provider_parse_count();
    free(long_needed_consumer);
    if (!long_needed_rejected
        || long_needed_bytes != (uint64_t)(maximum_accepted_needed_length() + 1U)
        || long_needed_work >= TEST_PROVIDER_AGGREGATE_WORK_BUDGET
        || long_needed_rela_calls != 0U
        || provider_parse_count_after_long_needed != provider_parse_count_before_long_needed) {
        (void)fprintf(stderr,
            "long DT_NEEDED was not bounded/rejected before provider parsing and loader work: rejected=%d work=%llu scanned=%llu rela_calls=%llu provider_parses=%llu->%llu\n",
            long_needed_rejected, (unsigned long long)long_needed_work,
            (unsigned long long)long_needed_bytes,
            (unsigned long long)long_needed_rela_calls,
            (unsigned long long)provider_parse_count_before_long_needed,
            (unsigned long long)provider_parse_count_after_long_needed);
        return 1;
    }

    size_t exact_dependency_count = 0U;
    int exact_uses_provider = 0;
    uint64_t exact_got_virtual_address = 0U;
    urp_host_image_validation_test_set_provider_work_limit(exact_consumer_candidate_work);
    urp_status exact_consumer_status = urp_host_image_validate_with_provider(
        consumer_bytes, consumer_size, URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME,
        &exact_dependency_count, &exact_uses_provider, &exact_got_virtual_address);
    uint64_t exact_consumer_work_used =
        urp_host_image_validation_test_provider_candidate_work_used();
    uint64_t exact_dynamic_entries =
        urp_host_image_validation_test_provider_candidate_dynamic_entries();
    uint64_t exact_range_work =
        urp_host_image_validation_test_provider_candidate_range_work();
    uint64_t exact_needed_string_bytes =
        urp_host_image_validation_test_provider_candidate_needed_string_bytes();
    uint64_t exact_consumer_budgeted_calls =
        urp_host_image_validation_test_consumer_rela_validation_count();
    urp_host_image_validation_test_set_provider_work_limit(
        TEST_PROVIDER_AGGREGATE_WORK_BUDGET);
    if (exact_consumer_status != URP_STATUS_OK
        || exact_dependency_count != 1U || !exact_uses_provider
        || exact_got_virtual_address != got_virtual_address
        || exact_consumer_work_used != exact_consumer_candidate_work
        || exact_dynamic_entries != candidate_dynamic_entries
        || exact_range_work != candidate_range_work
        || exact_needed_string_bytes != candidate_needed_string_bytes
        || exact_consumer_budgeted_calls != 1U) {
        (void)fprintf(stderr,
            "consumer candidate exact aggregate-work limit failed: status=%d work=%llu required=%llu dynamic=%llu ranges=%llu needed_bytes=%llu budgeted_calls=%llu\n",
            (int)exact_consumer_status,
            (unsigned long long)exact_consumer_work_used,
            (unsigned long long)exact_consumer_candidate_work,
            (unsigned long long)exact_dynamic_entries,
            (unsigned long long)exact_range_work,
            (unsigned long long)exact_needed_string_bytes,
            (unsigned long long)exact_consumer_budgeted_calls);
        return 1;
    }

    urp_host_adapter_v1 consumer_over_limit_adapter;
    uint64_t provider_parse_count_before_consumer_limit =
        urp_host_image_validation_test_provider_parse_count();
    urp_host_image_validation_test_set_provider_work_limit(exact_consumer_candidate_work - 1U);
    int consumer_over_limit_rejected = configured_adapter(
            &consumer_over_limit_adapter, argv[1],
            URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME, build_id, sha256)
        && expect_rejected(&consumer_over_limit_adapter, consumer_bytes, consumer_size);
    uint64_t consumer_over_limit_work_used =
        urp_host_image_validation_test_provider_candidate_work_used();
    uint64_t consumer_over_limit_budgeted_calls =
        urp_host_image_validation_test_consumer_rela_validation_count();
    uint64_t provider_parse_count_after_consumer_limit =
        urp_host_image_validation_test_provider_parse_count();
    urp_host_image_validation_test_set_provider_work_limit(
        TEST_PROVIDER_AGGREGATE_WORK_BUDGET);
    if (!consumer_over_limit_rejected
        || consumer_over_limit_budgeted_calls != 1U
        || consumer_over_limit_work_used >= exact_consumer_candidate_work
        || provider_parse_count_after_consumer_limit
            != provider_parse_count_before_consumer_limit) {
        (void)fprintf(stderr,
            "consumer candidate one-under aggregate limit did not reject before provider parse/memfd/loader: rejected=%d work=%llu required=%llu budgeted_calls=%llu provider_parses=%llu->%llu\n",
            consumer_over_limit_rejected,
            (unsigned long long)consumer_over_limit_work_used,
            (unsigned long long)exact_consumer_candidate_work,
            (unsigned long long)consumer_over_limit_budgeted_calls,
            (unsigned long long)provider_parse_count_before_consumer_limit,
            (unsigned long long)provider_parse_count_after_consumer_limit);
        return 1;
    }

    urp_status provider_validation = urp_host_external_provider_validate(
        provider_bytes, provider_size, URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME,
        build_id, &provider_facts);
    if (provider_validation != URP_STATUS_OK) {
        (void)fprintf(stderr, "pinned provider parser rejected the valid provider: status=%d\n",
            (int)provider_validation);
        return 1;
    }
    uint64_t exact_provider_parse_work =
        urp_host_image_validation_test_provider_parse_work_used();
    if (exact_provider_parse_work == 0U) {
        (void)fprintf(stderr, "pinned provider parser work counter was not recorded\n");
        return 1;
    }
    uint64_t provider_parse_count_before_exact =
        urp_host_image_validation_test_provider_parse_count();
    urp_host_image_validation_test_set_provider_work_limit(exact_provider_parse_work);
    urp_status exact_provider_parse_status = urp_host_external_provider_validate(
        provider_bytes, provider_size, URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME,
        build_id, &provider_facts);
    uint64_t exact_provider_parse_work_used =
        urp_host_image_validation_test_provider_parse_work_used();
    uint64_t exact_provider_parse_count =
        urp_host_image_validation_test_provider_parse_count();
    urp_host_image_validation_test_set_provider_work_limit(
        TEST_PROVIDER_AGGREGATE_WORK_BUDGET);
    if (exact_provider_parse_status != URP_STATUS_OK
        || exact_provider_parse_work_used != exact_provider_parse_work
        || exact_provider_parse_count != provider_parse_count_before_exact + 1U) {
        (void)fprintf(stderr,
            "pinned provider parser exact aggregate-work limit failed: status=%d work=%llu required=%llu\n",
            (int)exact_provider_parse_status,
            (unsigned long long)exact_provider_parse_work_used,
            (unsigned long long)exact_provider_parse_work);
        return 1;
    }
    uint64_t provider_parse_count_before_one_under =
        urp_host_image_validation_test_provider_parse_count();
    urp_host_external_provider_facts provider_one_under_facts;
    urp_host_image_validation_test_set_provider_work_limit(exact_provider_parse_work - 1U);
    urp_status provider_parse_one_under_status = urp_host_external_provider_validate(
        provider_bytes, provider_size, URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME,
        build_id, &provider_one_under_facts);
    uint64_t provider_parse_one_under_work =
        urp_host_image_validation_test_provider_parse_work_used();
    uint64_t provider_parse_count_after_one_under =
        urp_host_image_validation_test_provider_parse_count();
    urp_host_image_validation_test_set_provider_work_limit(
        TEST_PROVIDER_AGGREGATE_WORK_BUDGET);
    if (provider_parse_one_under_status == URP_STATUS_OK
        || provider_parse_one_under_work >= exact_provider_parse_work
        || provider_parse_count_after_one_under != provider_parse_count_before_one_under + 1U) {
        (void)fprintf(stderr,
            "pinned provider parser one-under aggregate-work limit was not rejected: status=%d work=%llu required=%llu\n",
            (int)provider_parse_one_under_status,
            (unsigned long long)provider_parse_one_under_work,
            (unsigned long long)exact_provider_parse_work);
        return 1;
    }

    urp_host_adapter_v1 missing_config_adapter;
    urp_host_adapter_init(&missing_config_adapter);
    if (!expect_rejected(&missing_config_adapter, consumer_bytes, consumer_size)) {
        (void)fprintf(stderr, "missing provider configuration was not rejected before memfd/load\n");
        return 1;
    }

    urp_host_adapter_v1 negative_adapter;
    void *missing_dependency_global_handle = dlopen(argv[7], RTLD_NOW | RTLD_GLOBAL);
    if (missing_dependency_global_handle == NULL) {
        (void)fprintf(stderr, "global table-symbol negative fixture failed to preload: %s\n", dlerror());
        return 1;
    }
    urp_host_adapter_init(&negative_adapter);
    int missing_dependency_rejected =
        expect_rejected(&negative_adapter, missing_dependency_bytes, missing_dependency_size)
        && configured_adapter(&negative_adapter, argv[1],
            URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME, build_id, sha256)
        && expect_rejected(&negative_adapter, missing_dependency_bytes, missing_dependency_size);
    int missing_dependency_global_close = dlclose(missing_dependency_global_handle);
    if (!missing_dependency_rejected || missing_dependency_global_close != 0) {
        (void)fprintf(stderr,
            "missing provider DT_NEEDED was not rejected before memfd/load with both adapter configurations\n");
        return 1;
    }
    char wrong_hash[URP_HOST_PROVIDER_SHA256_HEX_CAPACITY];
    memcpy(wrong_hash, sha256, sizeof(wrong_hash));
    wrong_hash[0] = wrong_hash[0] == '0' ? '1' : '0';
    uint64_t provider_parse_count_before_hash_negative =
        urp_host_image_validation_test_provider_parse_count();
    if (!configured_adapter(&negative_adapter, argv[1], URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME,
            build_id, wrong_hash)
        || !expect_rejected(&negative_adapter, consumer_bytes, consumer_size)
        || urp_host_image_validation_test_provider_parse_count()
            != provider_parse_count_before_hash_negative) {
        (void)fprintf(stderr, "provider SHA-256 mismatch was not rejected before parse/memfd\n");
        return 1;
    }
    char wrong_build_id[URP_HOST_PROVIDER_BUILD_ID_HEX_CAPACITY];
    memcpy(wrong_build_id, build_id, sizeof(wrong_build_id));
    wrong_build_id[0] = wrong_build_id[0] == '0' ? '1' : '0';
    if (!configured_adapter(&negative_adapter, argv[1], URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME,
            wrong_build_id, sha256)
        || !expect_rejected(&negative_adapter, consumer_bytes, consumer_size)) {
        (void)fprintf(stderr, "provider build-id mismatch was not rejected before memfd\n");
        return 1;
    }
    if (!configured_adapter(&negative_adapter,
            "/this/host/provider/path/does/not/exist.so",
            URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME, build_id, sha256)
        || !expect_rejected_with_status(
            &negative_adapter, consumer_bytes, consumer_size, URP_STATUS_LOAD_FAILED)) {
        (void)fprintf(stderr, "absent configured provider was not rejected before memfd\n");
        return 1;
    }
    urp_host_provider_config_v1 wrong_soname_config = {
        .path = argv[1],
        .expected_soname = "liburprotect-untrusted-provider.so.1",
        .expected_build_id_hex = build_id,
        .expected_sha256_hex = sha256,
    };
    if (urp_host_adapter_init_with_provider(&negative_adapter, &wrong_soname_config)
        != URP_STATUS_INVALID_ARGUMENT) {
        (void)fprintf(stderr, "noncanonical provider identity configuration was accepted\n");
        return 1;
    }

    char bad_build_id[URP_HOST_PROVIDER_BUILD_ID_HEX_CAPACITY] = {0};
    char bad_sha256[URP_HOST_PROVIDER_SHA256_HEX_CAPACITY] = {0};
    char dependency_build_id[URP_HOST_PROVIDER_BUILD_ID_HEX_CAPACITY] = {0};
    char dependency_sha256[URP_HOST_PROVIDER_SHA256_HEX_CAPACITY] = {0};
    char wrong_soname_build_id[URP_HOST_PROVIDER_BUILD_ID_HEX_CAPACITY] = {0};
    char wrong_soname_sha256[URP_HOST_PROVIDER_SHA256_HEX_CAPACITY] = {0};
    if (!identify_provider(argv[3], bad_build_id, bad_sha256)
        || !identify_provider(argv[4], wrong_soname_build_id, wrong_soname_sha256)
        || !identify_provider(argv[5], dependency_build_id, dependency_sha256)) {
        (void)fprintf(stderr, "negative provider fixture identity parse failed\n");
        return 1;
    }
    if (!configured_adapter(&negative_adapter, argv[3], URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME,
            bad_build_id, bad_sha256)
        || !expect_rejected(&negative_adapter, consumer_bytes, consumer_size)) {
        (void)fprintf(stderr, "malformed provider object/range was not rejected before memfd\n");
        return 1;
    }
    if (!configured_adapter(&negative_adapter, argv[4], URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME,
            wrong_soname_build_id, wrong_soname_sha256)
        || !expect_rejected(&negative_adapter, consumer_bytes, consumer_size)) {
        (void)fprintf(stderr, "provider SONAME mismatch was not rejected before memfd\n");
        return 1;
    }
    if (!configured_adapter(&negative_adapter, argv[5], URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME,
            dependency_build_id, dependency_sha256)
        || !expect_rejected(&negative_adapter, consumer_bytes, consumer_size)) {
        (void)fprintf(stderr, "unexpected provider dependency was not rejected before memfd\n");
        return 1;
    }
    if (!configured_adapter(&negative_adapter, argv[1], URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME,
            build_id, sha256)
        || !expect_rejected(&negative_adapter, bad_consumer_bytes, bad_consumer_size)) {
        (void)fprintf(stderr, "image/provider SONAME mismatch was not rejected before memfd\n");
        return 1;
    }

    void *conflict_handle = dlopen(argv[6], RTLD_NOW | RTLD_GLOBAL);
    if (conflict_handle == NULL) {
        (void)fprintf(stderr, "same-SONAME conflict fixture failed to preload: %s\n", dlerror());
        return 1;
    }
    int conflict_rejected = configured_adapter(
            &negative_adapter, argv[1], URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME, build_id, sha256)
        && expect_rejected(&negative_adapter, consumer_bytes, consumer_size);
    int conflict_close_status = dlclose(conflict_handle);
    if (!conflict_rejected || conflict_close_status != 0) {
        (void)fprintf(stderr, "conflicting same-SONAME mapping was not rejected\n");
        return 1;
    }
    urp_host_adapter_v1 adapter;
    if (!configured_adapter(&adapter, argv[1], URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME,
            build_id, sha256)) {
        (void)fprintf(stderr, "trusted provider adapter initialization failed\n");
        return 1;
    }
    urp_image_handle handle = 0U;
    status = adapter.context.load_image(
        adapter.context.userdata, consumer_bytes, consumer_size,
        URP_LOAD_IMAGE_IMMUTABLE, &handle);
    if (status != URP_STATUS_OK || handle == 0U || !urp_host_adapter_image_is_sealed(handle)) {
        (void)fprintf(stderr, "trusted provider consumer load failed: status=%d handle=%llu\n",
            (int)status, (unsigned long long)handle);
        free(provider_bytes);
        free(consumer_bytes);
        free(bad_consumer_bytes);
        return 1;
    }

    uintptr_t entry_address = 0U;
    uintptr_t observer_address = 0U;
    uintptr_t table_address = 0U;
    static const char *const target_names[] = {
        "urp_provider_target_0", "urp_provider_target_1",
        "urp_provider_target_2", "urp_provider_target_3"
    };
    uintptr_t target_addresses[4] = {0};
    if (adapter.context.lookup_symbol(adapter.context.userdata, handle,
            "urp_entry", NULL, &entry_address) != URP_STATUS_OK
        || adapter.context.lookup_symbol(adapter.context.userdata, handle,
            "urp_observer", NULL, &observer_address) != URP_STATUS_OK
        || adapter.context.lookup_symbol(adapter.context.userdata, handle,
            URP_HOST_EXTERNAL_TABLE_SYMBOL, NULL, &table_address) != URP_STATUS_OK
        || entry_address == 0U || observer_address == 0U || table_address == 0U) {
        (void)adapter.context.release_image(adapter.context.userdata, handle);
        (void)fprintf(stderr, "provider consumer symbols did not resolve\n");
        return 1;
    }
    for (size_t index = 0U; index < 4U; ++index) {
        uint32_t raw_offset = read_u32(provider_facts.table_bytes + index * sizeof(uint32_t));
        int64_t displacement = (raw_offset & UINT32_C(0x80000000)) != 0U
            ? (int64_t)raw_offset - INT64_C(0x100000000) : (int64_t)raw_offset;
        if (displacement < 0) {
            uint64_t magnitude = (uint64_t)(-displacement);
            if (magnitude > (uint64_t)table_address) {
                (void)adapter.context.release_image(adapter.context.userdata, handle);
                (void)fprintf(stderr, "provider target offset underflow\n");
                return 1;
            }
            target_addresses[index] = table_address - (uintptr_t)magnitude;
        } else {
            uint64_t magnitude = (uint64_t)displacement;
            if (magnitude > (uint64_t)UINTPTR_MAX - table_address) {
                (void)adapter.context.release_image(adapter.context.userdata, handle);
                (void)fprintf(stderr, "provider target offset overflow\n");
                return 1;
            }
            target_addresses[index] = table_address + (uintptr_t)magnitude;
        }
    }

    struct link_map *provider_map = NULL;
    struct link_map *consumer_map = NULL;
    Dl_info provider_info;
    Dl_info consumer_info;
    if (dladdr1((void *)table_address, &provider_info, (void **)&provider_map, RTLD_DL_LINKMAP) == 0
        || provider_map == NULL
        || dladdr1((void *)entry_address, &consumer_info, (void **)&consumer_map, RTLD_DL_LINKMAP) == 0
        || consumer_map == NULL) {
        (void)adapter.context.release_image(adapter.context.userdata, handle);
        (void)fprintf(stderr, "loaded provider/consumer mapping identity unavailable\n");
        return 1;
    }
    char provider_loaded_path[4096] = {0};
    char consumer_loaded_path[4096] = {0};
    if (provider_info.dli_fname == NULL || consumer_info.dli_fname == NULL
        || strnlen(provider_info.dli_fname, sizeof(provider_loaded_path)) >= sizeof(provider_loaded_path)
        || strnlen(consumer_info.dli_fname, sizeof(consumer_loaded_path)) >= sizeof(consumer_loaded_path)) {
        (void)adapter.context.release_image(adapter.context.userdata, handle);
        (void)fprintf(stderr, "provider or consumer mapped path is not bounded\n");
        return 1;
    }
    memcpy(provider_loaded_path, provider_info.dli_fname, strlen(provider_info.dli_fname) + 1U);
    memcpy(consumer_loaded_path, consumer_info.dli_fname, strlen(consumer_info.dli_fname) + 1U);
    for (size_t index = 0U; index < 4U; ++index) {
        struct link_map *target_map = NULL;
        Dl_info target_info;
        if (dladdr1((void *)target_addresses[index], &target_info,
                (void **)&target_map, RTLD_DL_LINKMAP) == 0 || target_map != provider_map) {
            (void)adapter.context.release_image(adapter.context.userdata, handle);
            (void)fprintf(stderr, "target %s is not provider-local\n", target_names[index]);
            return 1;
        }
    }

    provider_relocation_facts runtime_relocation = {0};
    if (!consumer_provider_relocation(consumer_bytes, consumer_size, &runtime_relocation)
        || runtime_relocation.got_virtual_address != got_virtual_address
        || (uint64_t)consumer_map->l_addr > (uint64_t)UINTPTR_MAX - got_virtual_address) {
        (void)adapter.context.release_image(adapter.context.userdata, handle);
        (void)fprintf(stderr, "consumer GLOB_DAT runtime mapping is invalid\n");
        return 1;
    }
    uintptr_t got_address = (uintptr_t)consumer_map->l_addr + (uintptr_t)got_virtual_address;
    uintptr_t got_value = 0U;
    memcpy(&got_value, (const void *)got_address, sizeof(got_value));
    if (got_value != table_address || table_address != (uintptr_t)provider_map->l_addr
            + (uintptr_t)provider_facts.table_virtual_address) {
        (void)adapter.context.release_image(adapter.context.userdata, handle);
        (void)fprintf(stderr, "GOT slot did not resolve to the validated provider table\n");
        return 1;
    }
    char table_permissions[5] = {0};
    char table_mapping_line[4096] = {0};
    if (!address_mapping(table_address, table_permissions, table_mapping_line,
            sizeof(table_mapping_line))
        || table_permissions[0] != 'r' || table_permissions[1] != '-'
        || table_permissions[2] != '-') {
        (void)adapter.context.release_image(adapter.context.userdata, handle);
        (void)fprintf(stderr, "provider table mapping is not read-only\n");
        return 1;
    }
    size_t table_mapping_length = strnlen(table_mapping_line, sizeof(table_mapping_line));
    while (table_mapping_length != 0U
        && (table_mapping_line[table_mapping_length - 1U] == '\n'
            || table_mapping_line[table_mapping_length - 1U] == '\r')) {
        table_mapping_line[--table_mapping_length] = '\0';
    }

    urp_entry_fn entry = NULL;
    urp_entry_fn observer = NULL;
    memcpy(&entry, &entry_address, sizeof(entry));
    memcpy(&observer, &observer_address, sizeof(observer));
    uint8_t table_before[16];
    memcpy(table_before, (const void *)table_address, sizeof(table_before));
    if (memcmp(table_before, provider_facts.table_bytes, sizeof(table_before)) != 0) {
        (void)adapter.context.release_image(adapter.context.userdata, handle);
        (void)fprintf(stderr, "runtime provider table differs from trusted provider bytes\n");
        return 1;
    }
    static const int32_t expected_statuses[4] = {17, 103, -7, 91};
    int32_t entry_statuses[5] = {0};
    int32_t observer_statuses[5] = {0};
    size_t stdout_sizes[5] = {0U};
    size_t stderr_sizes[5] = {0U};
    uint8_t stdout_captures[5][TEST_CAPTURE_LIMIT] = {{0}};
    uint8_t stderr_captures[5][TEST_CAPTURE_LIMIT] = {{0}};
    for (uint32_t index = 0U; index < 5U; ++index) {
        if (!capture_dispatch(entry, observer, &adapter.context, index,
                &entry_statuses[index], &observer_statuses[index],
                stdout_captures[index], &stdout_sizes[index],
                stderr_captures[index], &stderr_sizes[index])) {
            (void)adapter.context.release_image(adapter.context.userdata, handle);
            (void)fprintf(stderr, "could not capture consumer/observer streams\n");
            return 1;
        }
        int32_t expected = index < 4U ? expected_statuses[index] : -1;
        if (entry_statuses[index] != expected || observer_statuses[index] != expected
            || stdout_sizes[index] != 0U || stderr_sizes[index] != 0U
            || memcmp(table_before, (const void *)table_address, sizeof(table_before)) != 0) {
            (void)adapter.context.release_image(adapter.context.userdata, handle);
            (void)fprintf(stderr, "dispatch or observer control failed for index %u\n", index);
            return 1;
        }
    }

    urp_status release_status = adapter.context.release_image(adapter.context.userdata, handle);
    int mapping_gone = no_mapping_at(table_address);
    if (release_status != URP_STATUS_OK || !mapping_gone) {
        (void)fprintf(stderr, "provider lifetime/release contract failed: release=%d mapped=%d\n",
            (int)release_status, !mapping_gone);
        return 1;
    }
    void *symbol_conflict_handle = dlopen(argv[7], RTLD_NOW | RTLD_GLOBAL);
    if (symbol_conflict_handle == NULL) {
        (void)fprintf(stderr, "different-SONAME table-symbol conflict failed to preload: %s\n", dlerror());
        return 1;
    }
    uintptr_t isolated_entry_address = 0U;
    uintptr_t isolated_table_address = 0U;
    urp_image_handle isolated_handle = 0U;
    int isolated_load_ok = configured_adapter(
            &negative_adapter, argv[1], URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME, build_id, sha256)
        && negative_adapter.context.load_image(
            negative_adapter.context.userdata, consumer_bytes, consumer_size,
            URP_LOAD_IMAGE_IMMUTABLE, &isolated_handle) == URP_STATUS_OK
        && isolated_handle != 0U
        && negative_adapter.context.lookup_symbol(
            negative_adapter.context.userdata, isolated_handle, "urp_entry", NULL,
            &isolated_entry_address) == URP_STATUS_OK
        && negative_adapter.context.lookup_symbol(
            negative_adapter.context.userdata, isolated_handle,
            URP_HOST_EXTERNAL_TABLE_SYMBOL, NULL, &isolated_table_address) == URP_STATUS_OK;
    void *ambient_table = dlsym(RTLD_DEFAULT, URP_HOST_EXTERNAL_TABLE_SYMBOL);
    int isolated_binding_ok = 0;
    if (isolated_load_ok && ambient_table != NULL
        && isolated_table_address != (uintptr_t)ambient_table
        && memcmp((const void *)isolated_table_address, provider_facts.table_bytes,
            sizeof(provider_facts.table_bytes)) == 0) {
        urp_entry_fn isolated_entry = NULL;
        memcpy(&isolated_entry, &isolated_entry_address, sizeof(isolated_entry));
        urp_entry_fn isolated_observer = NULL;
        uintptr_t isolated_observer_address = 0U;
        if (negative_adapter.context.lookup_symbol(
                negative_adapter.context.userdata, isolated_handle, "urp_observer", NULL,
                &isolated_observer_address) == URP_STATUS_OK) {
            memcpy(&isolated_observer, &isolated_observer_address, sizeof(isolated_observer));
            int32_t isolated_entry_status = 0;
            int32_t isolated_observer_status = 0;
            size_t isolated_stdout_size = 0U;
            size_t isolated_stderr_size = 0U;
            uint8_t isolated_stdout[TEST_CAPTURE_LIMIT] = {0};
            uint8_t isolated_stderr[TEST_CAPTURE_LIMIT] = {0};
            isolated_binding_ok = capture_dispatch(
                isolated_entry, isolated_observer, &negative_adapter.context, 0U,
                &isolated_entry_status, &isolated_observer_status,
                isolated_stdout, &isolated_stdout_size,
                isolated_stderr, &isolated_stderr_size)
                && isolated_entry_status == 17 && isolated_observer_status == 17
                && isolated_stdout_size == 0U && isolated_stderr_size == 0U;
        }
    }
    urp_status isolated_release_status = URP_STATUS_OK;
    if (isolated_handle != 0U) {
        isolated_release_status = negative_adapter.context.release_image(
            negative_adapter.context.userdata, isolated_handle);
    }
    int symbol_conflict_close_status = dlclose(symbol_conflict_handle);
    if (!isolated_load_ok || !isolated_binding_ok
        || isolated_release_status != URP_STATUS_OK || symbol_conflict_close_status != 0) {
        (void)fprintf(stderr,
            "isolated provider binding did not bypass different-SONAME global symbol\n");
        return 1;
    }

    char table_bytes_hex[33];
    char stdout_hex[5][TEST_CAPTURE_LIMIT * 2U + 1U];
    char stderr_hex[5][TEST_CAPTURE_LIMIT * 2U + 1U];
    bytes_hex(table_before, sizeof(table_before), table_bytes_hex);
    for (size_t index = 0U; index < 5U; ++index) {
        bytes_hex(stdout_captures[index], stdout_sizes[index], stdout_hex[index]);
        bytes_hex(stderr_captures[index], stderr_sizes[index], stderr_hex[index]);
    }
    (void)printf(
        "{\"schemaVersion\":1,\"provider\":{\"soname\":\"%s\",\"buildId\":\"%s\",\"sha256\":\"%s\",\"mappedPath\":\"%s\",\"tableAddress\":\"0x%llx\",\"tableBytes\":\"%s\",\"tablePermissions\":\"%s\",\"tableMapping\":\"%s\"},"
        "\"consumer\":{\"mappedPath\":\"%s\",\"entryAddress\":\"0x%llx\",\"observerAddress\":\"0x%llx\",\"dependencies\":1,\"relocationType\":%u,\"gotVirtualAddress\":\"0x%llx\",\"gotAddress\":\"0x%llx\",\"gotValue\":\"0x%llx\",\"imageSealed\":true},"
        "\"sourceEntryStatuses\":[%d,%d,%d,%d,%d],\"observerStatuses\":[%d,%d,%d,%d,%d],"
        "\"dispatchStdoutHex\":[\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"],"
        "\"dispatchStderrHex\":[\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"],"
        "\"observerTableUnchanged\":true,\"providerTargets\":[\"%s\",\"%s\",\"%s\",\"%s\"],"
        "\"providerTargetAddresses\":[\"0x%llx\",\"0x%llx\",\"0x%llx\",\"0x%llx\"],"
        "\"releaseStatus\":%d,\"providerReleasedAfterConsumer\":true,\"failClosedNegatives\":18}\n",
        URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME, build_id, sha256,
        provider_loaded_path,
        (unsigned long long)table_address, table_bytes_hex, table_permissions, table_mapping_line,
        consumer_loaded_path, (unsigned long long)entry_address, (unsigned long long)observer_address,
        runtime_relocation.relocation_type,
        (unsigned long long)got_virtual_address, (unsigned long long)got_address,
        (unsigned long long)got_value,
        entry_statuses[0], entry_statuses[1], entry_statuses[2], entry_statuses[3], entry_statuses[4],
        observer_statuses[0], observer_statuses[1], observer_statuses[2], observer_statuses[3], observer_statuses[4],
        stdout_hex[0], stdout_hex[1], stdout_hex[2], stdout_hex[3], stdout_hex[4],
        stderr_hex[0], stderr_hex[1], stderr_hex[2], stderr_hex[3], stderr_hex[4],
        target_names[0], target_names[1], target_names[2], target_names[3],
        (unsigned long long)target_addresses[0], (unsigned long long)target_addresses[1],
        (unsigned long long)target_addresses[2], (unsigned long long)target_addresses[3],
        (int)release_status);

    free(provider_bytes);
    free(consumer_bytes);
    free(bad_consumer_bytes);
    return 0;
}
