#define _GNU_SOURCE

#include "host_image_validation.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define URP_ELF_HEADER_SIZE 64U
#define URP_ELF_PROGRAM_HEADER_SIZE 56U
#define URP_ELF_DYNAMIC_ENTRY_SIZE 16U
#define URP_ELF_CLASS_64 2U
#define URP_ELF_DATA_LSB 1U
#define URP_ELF_VERSION_CURRENT 1U
#define URP_ELF_MACHINE_AARCH64 183U
#define URP_ELF_TYPE_DYN 3U
#define URP_PT_LOAD 1U
#define URP_PT_DYNAMIC 2U
#define URP_PT_INTERP 3U
#define URP_PT_TLS 7U
#define URP_PT_GNU_PROPERTY 0x6474e553U
#define URP_PT_GNU_STACK 0x6474e551U
#define URP_NOTE_GNU 5U
#define URP_GNU_PROPERTY_AARCH64_FEATURE_1_AND UINT32_C(0xC0000000)
#define URP_GNU_PROPERTY_AARCH64_FEATURE_1_BTI UINT32_C(1)
#define URP_GNU_PROPERTY_AARCH64_FEATURE_1_PAC UINT32_C(2)
#define URP_PF_W 2U
#define URP_PF_X 1U
#define URP_DT_NEEDED 1U
#define URP_DT_PLTRELSZ 2U
#define URP_DT_PLTGOT 3U
#define URP_DT_HASH 4U
#define URP_DT_STRTAB 5U
#define URP_DT_SYMTAB 6U
#define URP_DT_RELA 7U
#define URP_DT_RELASZ 8U
#define URP_DT_RELAENT 9U
#define URP_DT_STRSZ 10U
#define URP_DT_SYMENT 11U
#define URP_DT_STRTAB 5U
#define URP_DT_STRSZ 10U
#define URP_R_AARCH64_ABS64 257U
#define URP_R_AARCH64_GLOB_DAT 1025U
#define URP_R_AARCH64_JUMP_SLOT 1026U
#define URP_R_AARCH64_TLS_TPREL64 1030U
#define URP_DT_INIT 12U
#define URP_DT_FINI 13U
#define URP_DT_SONAME 14U
#define URP_DT_RPATH 15U
#define URP_DT_SYMBOLIC 16U
#define URP_DT_REL 17U
#define URP_DT_RELSZ 18U
#define URP_DT_RELENT 19U
#define URP_DT_PLTREL 20U
#define URP_DT_DEBUG 21U
#define URP_DT_TEXTREL 22U
#define URP_DT_JMPREL 23U
#define URP_DT_BIND_NOW 24U
#define URP_DT_INIT_ARRAY 25U
#define URP_DT_FINI_ARRAY 26U
#define URP_DT_INIT_ARRAYSZ 27U
#define URP_DT_FINI_ARRAYSZ 28U
#define URP_DT_RUNPATH 29U
#define URP_DT_FLAGS 30U
#define URP_DT_PREINIT_ARRAY 32U
#define URP_DT_PREINIT_ARRAYSZ 33U
#define URP_DT_RELRSZ 35U
#define URP_DT_RELR 36U
#define URP_DT_RELRENT 37U
#define URP_DT_ANDROID_REL UINT64_C(0x6000000f)
#define URP_DT_ANDROID_RELSZ UINT64_C(0x60000010)
#define URP_DT_ANDROID_RELA UINT64_C(0x60000011)
#define URP_DT_ANDROID_RELASZ UINT64_C(0x60000012)
#define URP_DT_ANDROID_RELR UINT64_C(0x6fffe000)
#define URP_DT_ANDROID_RELRSZ UINT64_C(0x6fffe001)
#define URP_DT_ANDROID_RELRENT UINT64_C(0x6fffe003)
#define URP_DT_ANDROID_RELRCOUNT UINT64_C(0x6fffe005)
#define URP_DT_VERSYM UINT64_C(0x6ffffff0)
#define URP_DT_GNU_HASH UINT64_C(0x6ffffef5)
#define URP_DT_VERDEF UINT64_C(0x6ffffffc)
#define URP_DT_VERDEFNUM UINT64_C(0x6ffffffd)
#define URP_DT_VERNEED UINT64_C(0x6ffffffe)
#define URP_DT_VERNEEDNUM UINT64_C(0x6fffffff)
#define URP_DT_FLAGS_1 UINT64_C(0x6ffffffb)
#define URP_DT_AUXILIARY UINT64_C(0x7ffffffd)
#define URP_DT_FILTER UINT64_C(0x7fffffff)
#define URP_DF_BIND_NOW UINT64_C(0x8)
#define URP_DF_1_NOW UINT64_C(0x1)
#define URP_STB_WEAK 2U
#define URP_STT_FUNC 2U
#define URP_STV_DEFAULT 0U
#define URP_SHN_UNDEF 0U
#define URP_R_AARCH64_RELATIVE 1027U
#define URP_MAX_PROGRAM_HEADERS 4096U
#define URP_MAX_DYNAMIC_ENTRIES (1U << 20)

typedef struct urp_dynamic_values {
    uint64_t strtab;
    uint64_t strsz;
    uint64_t needed_offset;
    uint64_t gnu_hash;
    uint64_t symtab;
    uint64_t syment;
    uint64_t versym;
    uint64_t verneed;
    uint64_t verneednum;
    uint64_t rela;
    uint64_t relasz;
    uint64_t relaent;
    uint64_t jmprel;
    uint64_t pltrelsz;
    uint64_t pltrel;
    uint64_t flags;
    uint64_t flags_1;
    uint64_t relr;
    uint64_t relrsz;
    uint64_t relrent;
    int has_rela;
    int has_symtab;
    int has_syment;
    int has_strtab;
    int has_strsz;
    int has_needed;
    int has_sysv_hash;
    int has_gnu_hash;
    int has_versym;
    int has_verneed;
    int has_verneednum;
    int has_relasz;
    int has_relaent;
    int has_relr;
    int has_relrsz;
    int has_relrent;
    int has_jmprel;
    int has_pltrelsz;
    int has_pltrel;
    int has_flags;
    int has_flags_1;
    int has_version_tags;
    int has_symbolic;
} urp_dynamic_values;

static uint16_t urp_read_u16_le(const uint8_t *bytes)
{
    return (uint16_t)bytes[0]
        | (uint16_t)((uint16_t)bytes[1] << 8U);
}

static uint32_t urp_read_u32_le(const uint8_t *bytes)
{
    return (uint32_t)bytes[0]
        | ((uint32_t)bytes[1] << 8U)
        | ((uint32_t)bytes[2] << 16U)
        | ((uint32_t)bytes[3] << 24U);
}

static uint64_t urp_read_u64_le(const uint8_t *bytes)
{
    uint64_t value = 0;
    for (size_t index = 0; index < 8U; ++index) {
        value |= (uint64_t)bytes[index] << (index * 8U);
    }
    return value;
}

static int urp_checked_add_u64(uint64_t left, uint64_t right, uint64_t *result)
{
    if (right > UINT64_MAX - left) {
        return 0;
    }
    *result = left + right;
    return 1;
}

static int urp_checked_mul_u64(uint64_t left, uint64_t right, uint64_t *result)
{
    if (left != 0U && right > UINT64_MAX / left) {
        return 0;
    }
    *result = left * right;
    return 1;
}

static int urp_u64_to_size(uint64_t value, size_t *result)
{
    if (result == NULL || value > (uint64_t)SIZE_MAX) {
        return 0;
    }
    *result = (size_t)value;
    return 1;
}

static int urp_range_in_file(
    size_t image_size,
    uint64_t offset,
    uint64_t length,
    size_t *offset_out,
    size_t *length_out);

static urp_status urp_validate_gnu_property(
    const uint8_t *image,
    size_t image_size,
    uint64_t offset,
    uint64_t size)
{
    size_t file_offset;
    size_t file_size;
    if (!urp_range_in_file(image_size, offset, size, &file_offset, &file_size)
        || file_size < 12U) {
        return URP_STATUS_UNSUPPORTED;
    }

    const uint8_t *note = image + file_offset;
    uint32_t namesz = urp_read_u32_le(note);
    uint32_t descsz = urp_read_u32_le(note + 4U);
    uint32_t type = urp_read_u32_le(note + 8U);
    uint64_t namesz_padded = ((uint64_t)namesz + UINT64_C(3)) & ~UINT64_C(3);
    uint64_t descsz_padded = ((uint64_t)descsz + UINT64_C(3)) & ~UINT64_C(3);
    uint64_t note_size;
    if (namesz != 4U
        || type != URP_NOTE_GNU
        || !urp_checked_add_u64(UINT64_C(12), namesz_padded, &note_size)
        || !urp_checked_add_u64(note_size, descsz_padded, &note_size)
        || note_size > (uint64_t)file_size) {
        return URP_STATUS_UNSUPPORTED;
    }

    if (memcmp(note + 12U, "GNU\0", 4U) != 0) {
        return URP_STATUS_UNSUPPORTED;
    }

    uint64_t property_offset;
    uint64_t descriptor_end;
    if (!urp_checked_add_u64(UINT64_C(12), namesz_padded, &property_offset)
        || !urp_checked_add_u64(property_offset, (uint64_t)descsz, &descriptor_end)) {
        return URP_STATUS_UNSUPPORTED;
    }

    uint64_t property_header_end;
    if (!urp_checked_add_u64(property_offset, UINT64_C(8), &property_header_end)
        || property_header_end > descriptor_end
        || property_offset > (uint64_t)SIZE_MAX) {
        return URP_STATUS_UNSUPPORTED;
    }
    const uint8_t *property = note + (size_t)property_offset;
    uint32_t property_type = urp_read_u32_le(property);
    uint32_t property_size = urp_read_u32_le(property + 4U);
    uint64_t property_data_size = ((uint64_t)property_size + UINT64_C(7))
        & ~UINT64_C(7);
    uint64_t property_data_end;
    if (property_type != URP_GNU_PROPERTY_AARCH64_FEATURE_1_AND
        || property_size != 4U
        || !urp_checked_add_u64(
            property_header_end,
            property_data_size,
            &property_data_end)
        || property_data_end > descriptor_end) {
        return URP_STATUS_UNSUPPORTED;
    }

    uint32_t features = urp_read_u32_le(property + 8U);
    if ((features & ~(URP_GNU_PROPERTY_AARCH64_FEATURE_1_BTI
        | URP_GNU_PROPERTY_AARCH64_FEATURE_1_PAC)) != 0U
        || features == 0U) {
        return URP_STATUS_UNSUPPORTED;
    }
    return URP_STATUS_OK;
}

static int urp_range_in_file(
    size_t image_size,
    uint64_t offset,
    uint64_t length,
    size_t *offset_out,
    size_t *length_out)
{
    uint64_t end;
    if (!urp_checked_add_u64(offset, length, &end)
        || end > (uint64_t)image_size
        || offset > (uint64_t)SIZE_MAX
        || length > (uint64_t)SIZE_MAX) {
        return 0;
    }
    if (offset_out != NULL) {
        *offset_out = (size_t)offset;
    }
    if (length_out != NULL) {
        *length_out = (size_t)length;
    }
    return 1;
}

static int urp_is_power_of_two(uint64_t value)
{
    return value == 0U || (value & (value - 1U)) == 0U;
}

static int urp_get_program_header(
    const uint8_t *image,
    size_t image_size,
    uint64_t program_header_offset,
    uint16_t program_header_count,
    uint16_t index,
    const uint8_t **header_out)
{
    if (index >= program_header_count || header_out == NULL) {
        return 0;
    }

    uint64_t index_offset;
    uint64_t header_offset;
    if (!urp_checked_mul_u64(
            (uint64_t)index,
            URP_ELF_PROGRAM_HEADER_SIZE,
            &index_offset)
        || !urp_checked_add_u64(program_header_offset, index_offset, &header_offset)) {
        return 0;
    }

    size_t offset;
    if (!urp_range_in_file(
            image_size,
            header_offset,
            URP_ELF_PROGRAM_HEADER_SIZE,
            &offset,
            NULL)) {
        return 0;
    }
    *header_out = image + offset;
    return 1;
}

static int urp_find_load_range(
    const uint8_t *image,
    size_t image_size,
    uint64_t program_header_offset,
    uint16_t program_header_count,
    uint64_t virtual_address,
    uint64_t length,
    uint32_t required_flags,
    int file_backed,
    size_t *file_offset_out)
{
    for (uint16_t index = 0; index < program_header_count; ++index) {
        const uint8_t *header;
        if (!urp_get_program_header(
                image,
                image_size,
                program_header_offset,
                program_header_count,
                index,
                &header)) {
            return 0;
        }

        if (urp_read_u32_le(header) != URP_PT_LOAD
            || (urp_read_u32_le(header + 4U) & required_flags) != required_flags) {
            continue;
        }

        uint64_t segment_address = urp_read_u64_le(header + 16U);
        uint64_t segment_size = urp_read_u64_le(header + (file_backed ? 32U : 40U));
        if (virtual_address < segment_address) {
            continue;
        }
        uint64_t delta = virtual_address - segment_address;
        if (delta > segment_size || length > segment_size - delta) {
            continue;
        }

        if (!file_backed) {
            return 1;
        }

        uint64_t file_offset;
        size_t resolved_file_offset;
        if (!urp_checked_add_u64(urp_read_u64_le(header + 8U), delta, &file_offset)
            || !urp_range_in_file(image_size, file_offset, length, &resolved_file_offset, NULL)) {
            return 0;
        }
        if (file_offset_out != NULL) {
            *file_offset_out = resolved_file_offset;
        }
        return 1;
    }
    return 0;
}

static int urp_validate_relocation_target(
    const uint8_t *image,
    size_t image_size,
    uint64_t program_header_offset,
    uint16_t program_header_count,
    uint64_t target)
{
    if (target % sizeof(uint64_t) != 0U) {
        return 0;
    }
    return urp_find_load_range(
        image,
        image_size,
        program_header_offset,
        program_header_count,
        target,
        sizeof(uint64_t),
        URP_PF_W,
        0,
        NULL);
}

static urp_status urp_validate_rela_table(
    const uint8_t *image,
    size_t image_size,
    const urp_dynamic_values *dynamic,
    uint64_t rela_address,
    uint64_t rela_size,
    uint64_t program_header_offset,
    uint16_t program_header_count)
{
    if (rela_size == 0U || rela_size % 24U != 0U) {
        return URP_STATUS_LOAD_FAILED;
    }

    size_t rela_offset;
    if (rela_size > (uint64_t)SIZE_MAX
        || !urp_find_load_range(
            image,
            image_size,
            program_header_offset,
            program_header_count,
            rela_address,
            rela_size,
            0U,
            1,
            &rela_offset)) {
        return URP_STATUS_LOAD_FAILED;
    }

    const uint8_t *rela = image + rela_offset;
    size_t entry_count = (size_t)rela_size / 24U;
    for (size_t index = 0; index < entry_count; ++index) {
        const uint8_t *entry = rela + index * 24U;
        uint64_t offset = urp_read_u64_le(entry);
        uint64_t info = urp_read_u64_le(entry + 8U);
        uint32_t type = (uint32_t)info;
        uint64_t symbol = info >> 32U;
        int symbolic = type == URP_R_AARCH64_ABS64
            || type == URP_R_AARCH64_GLOB_DAT
            || type == URP_R_AARCH64_TLS_TPREL64;
        uint64_t symbol_delta = 0U;
        uint64_t symbol_address = 0U;
        int symbol_range_valid = 1;
        if (symbolic) {
            symbol_range_valid = dynamic->has_symtab
                && dynamic->has_syment
                && dynamic->syment == 24U
                && symbol != 0U
                && urp_checked_mul_u64(symbol, dynamic->syment, &symbol_delta)
                && urp_checked_add_u64(dynamic->symtab, symbol_delta, &symbol_address)
                && urp_find_load_range(
                    image,
                    image_size,
                    program_header_offset,
                    program_header_count,
                    symbol_address,
                    dynamic->syment,
                    0U,
                    1,
                    NULL);
        }
        if ((type != 0U && type != URP_R_AARCH64_RELATIVE && !symbolic)
            || (type == 0U && symbol != 0U)
            || (type == URP_R_AARCH64_RELATIVE && symbol != 0U)
            || (symbolic && !symbol_range_valid)
            || !urp_validate_relocation_target(
                image,
                image_size,
                program_header_offset,
                program_header_count,
                offset)) {
            return URP_STATUS_UNSUPPORTED;
        }
    }
    return URP_STATUS_OK;
}

static urp_status urp_validate_rela(
    const uint8_t *image,
    size_t image_size,
    const urp_dynamic_values *dynamic,
    uint64_t program_header_offset,
    uint16_t program_header_count)
{
    if (!dynamic->has_rela && (dynamic->has_relasz || dynamic->has_relaent)) {
        return URP_STATUS_LOAD_FAILED;
    }
    if (!dynamic->has_rela) {
        return URP_STATUS_OK;
    }
    if (!dynamic->has_relasz || !dynamic->has_relaent
        || dynamic->relaent != 24U) {
        return URP_STATUS_LOAD_FAILED;
    }
    return urp_validate_rela_table(
        image,
        image_size,
        dynamic,
        dynamic->rela,
        dynamic->relasz,
        program_header_offset,
        program_header_count);
}

static urp_status urp_validate_plt_rela_table(
    const uint8_t *image,
    size_t image_size,
    const urp_dynamic_values *dynamic,
    uint64_t program_header_offset,
    uint16_t program_header_count)
{
    if (dynamic->pltrelsz == 0U || dynamic->pltrelsz % 24U != 0U
        || dynamic->relaent != 24U || !dynamic->has_relaent
        || !dynamic->has_symtab || !dynamic->has_syment
        || dynamic->syment != 24U || dynamic->has_needed
        || dynamic->has_version_tags || dynamic->has_symbolic
        || !((dynamic->has_flags && (dynamic->flags & URP_DF_BIND_NOW) != 0U)
            || (dynamic->has_flags_1 && (dynamic->flags_1 & URP_DF_1_NOW) != 0U))) {
        return URP_STATUS_UNSUPPORTED;
    }

    size_t rela_offset;
    if (dynamic->pltrelsz > (uint64_t)SIZE_MAX
        || !urp_find_load_range(
            image,
            image_size,
            program_header_offset,
            program_header_count,
            dynamic->jmprel,
            dynamic->pltrelsz,
            0U,
            1,
            &rela_offset)) {
        return URP_STATUS_LOAD_FAILED;
    }

    const uint8_t *rela = image + rela_offset;
    size_t entry_count = (size_t)dynamic->pltrelsz / 24U;
    for (size_t index = 0U; index < entry_count; ++index) {
        const uint8_t *entry = rela + index * 24U;
        uint64_t target = urp_read_u64_le(entry);
        uint64_t info = urp_read_u64_le(entry + 8U);
        uint32_t type = (uint32_t)info;
        uint64_t symbol = info >> 32U;
        uint64_t symbol_delta;
        uint64_t symbol_address;
        size_t symbol_offset;
        if (type != URP_R_AARCH64_JUMP_SLOT || symbol == 0U
            || !urp_checked_mul_u64(symbol, dynamic->syment, &symbol_delta)
            || !urp_checked_add_u64(dynamic->symtab, symbol_delta, &symbol_address)
            || !urp_find_load_range(
                image, image_size, program_header_offset, program_header_count,
                symbol_address, dynamic->syment, 0U, 1, &symbol_offset)) {
            return URP_STATUS_UNSUPPORTED;
        }

        const uint8_t *symbol_record = image + symbol_offset;
        uint32_t name_offset = urp_read_u32_le(symbol_record);
        uint8_t info_byte = symbol_record[4U];
        uint8_t other = symbol_record[5U];
        uint16_t section_index = urp_read_u16_le(symbol_record + 6U);
        if ((info_byte >> 4U) != URP_STB_WEAK
            || (info_byte & 0x0fU) != URP_STT_FUNC
            || other != URP_STV_DEFAULT
            || section_index != URP_SHN_UNDEF
            || !dynamic->has_strtab || !dynamic->has_strsz
            || dynamic->strsz == 0U || name_offset >= dynamic->strsz
            || dynamic->strsz > (uint64_t)SIZE_MAX) {
            return URP_STATUS_UNSUPPORTED;
        }

        size_t strings_offset;
        if (!urp_find_load_range(
                image, image_size, program_header_offset, program_header_count,
                dynamic->strtab, dynamic->strsz, 0U, 1, &strings_offset)
            || name_offset > SIZE_MAX - strings_offset) {
            return URP_STATUS_LOAD_FAILED;
        }
        size_t name_file_offset = strings_offset + (size_t)name_offset;
        size_t remaining = (size_t)dynamic->strsz - (size_t)name_offset;
        if (remaining == 0U || image[name_file_offset] == 0U
            || memchr(image + name_file_offset, 0, remaining) == NULL
            || !urp_validate_relocation_target(
                image, image_size, program_header_offset, program_header_count, target)) {
            return URP_STATUS_UNSUPPORTED;
        }
    }
    return URP_STATUS_OK;
}

static urp_status urp_validate_plt_rela(
    const uint8_t *image,
    size_t image_size,
    const urp_dynamic_values *dynamic,
    uint64_t program_header_offset,
    uint16_t program_header_count)
{
    if (!dynamic->has_jmprel && (dynamic->has_pltrelsz || dynamic->has_pltrel)) {
        return URP_STATUS_UNSUPPORTED;
    }
    if (!dynamic->has_jmprel) {
        return URP_STATUS_OK;
    }
    if (!dynamic->has_pltrelsz || !dynamic->has_pltrel
        || dynamic->pltrel != URP_DT_RELA) {
        return URP_STATUS_UNSUPPORTED;
    }
    return urp_validate_plt_rela_table(
        image,
        image_size,
        dynamic,
        program_header_offset,
        program_header_count);
}

static int urp_dynamic_string(
    const uint8_t *image,
    size_t image_size,
    const urp_dynamic_values *dynamic,
    uint64_t program_header_offset,
    uint16_t program_header_count,
    uint64_t string_offset,
    const char **string_out,
    size_t *string_length_out)
{
    if (!dynamic->has_strtab || !dynamic->has_strsz
        || dynamic->strsz == 0U || dynamic->strsz > (uint64_t)SIZE_MAX
        || string_offset >= dynamic->strsz) {
        return 0;
    }

    size_t strings_offset;
    if (!urp_find_load_range(
            image,
            image_size,
            program_header_offset,
            program_header_count,
            dynamic->strtab,
            dynamic->strsz,
            0U,
            1,
            &strings_offset)
        || string_offset > SIZE_MAX - strings_offset) {
        return 0;
    }

    size_t relative_offset = (size_t)string_offset;
    size_t remaining = (size_t)dynamic->strsz - relative_offset;
    size_t file_offset = strings_offset + relative_offset;
    size_t length = strnlen((const char *)(image + file_offset), remaining);
    if (length == remaining) {
        return 0;
    }
    if (string_out != NULL) {
        *string_out = (const char *)(image + file_offset);
    }
    if (string_length_out != NULL) {
        *string_length_out = length;
    }
    return 1;
}

static uint32_t urp_elf_name_hash(const char *name, size_t length)
{
    uint32_t hash = 0U;
    for (size_t index = 0U; index < length; ++index) {
        hash = (hash << 4U) + (uint8_t)name[index];
        uint32_t high = hash & UINT32_C(0xf0000000);
        if (high != 0U) {
            hash ^= high >> 24U;
            hash &= ~high;
        }
    }
    return hash;
}

static int urp_gnu_hash_symbol_count(
    const uint8_t *image,
    size_t image_size,
    uint64_t hash_address,
    uint64_t program_header_offset,
    uint16_t program_header_count,
    uint64_t *symbol_count_out)
{
    size_t hash_offset;
    if (!urp_find_load_range(
            image,
            image_size,
            program_header_offset,
            program_header_count,
            hash_address,
            16U,
            0U,
            1,
            &hash_offset)) {
        return 0;
    }

    uint64_t bucket_count = urp_read_u32_le(image + hash_offset);
    uint64_t first_hashed_symbol = urp_read_u32_le(image + hash_offset + 4U);
    uint64_t bloom_word_count = urp_read_u32_le(image + hash_offset + 8U);
    uint64_t bloom_size;
    uint64_t bucket_size;
    uint64_t bucket_offset;
    uint64_t prefix_size;
    uint64_t chain_offset;
    if (bucket_count == 0U || first_hashed_symbol == 0U || bloom_word_count == 0U
        || bucket_count > URP_MAX_DYNAMIC_ENTRIES
        || first_hashed_symbol > URP_MAX_DYNAMIC_ENTRIES
        || bloom_word_count > URP_MAX_DYNAMIC_ENTRIES
        || !urp_checked_mul_u64(bloom_word_count, sizeof(uint64_t), &bloom_size)
        || !urp_checked_mul_u64(bucket_count, sizeof(uint32_t), &bucket_size)
        || !urp_checked_add_u64(16U, bloom_size, &bucket_offset)
        || !urp_checked_add_u64(bucket_offset, bucket_size, &prefix_size)
        || !urp_checked_add_u64(hash_address, prefix_size, &chain_offset)
        || !urp_find_load_range(
            image,
            image_size,
            program_header_offset,
            program_header_count,
            hash_address,
            prefix_size,
            0U,
            1,
            NULL)
        || prefix_size > (uint64_t)SIZE_MAX
        || bucket_offset > (uint64_t)SIZE_MAX
        || hash_offset > SIZE_MAX - (size_t)bucket_offset) {
        return 0;
    }

    size_t buckets_file_offset = hash_offset + (size_t)bucket_offset;
    uint64_t maximum_symbol_index = first_hashed_symbol - 1U;
    uint64_t total_chain_steps = 0U;
    int found_hashed_symbol = 0;
    for (uint64_t bucket_index = 0U; bucket_index < bucket_count; ++bucket_index) {
        uint64_t bucket_entry_offset;
        if (!urp_checked_mul_u64(bucket_index, sizeof(uint32_t), &bucket_entry_offset)
            || bucket_entry_offset > SIZE_MAX - buckets_file_offset) {
            return 0;
        }
        uint64_t symbol_index = urp_read_u32_le(
            image + buckets_file_offset + (size_t)bucket_entry_offset);
        if (symbol_index == 0U) {
            continue;
        }
        if (symbol_index < first_hashed_symbol
            || symbol_index > URP_MAX_DYNAMIC_ENTRIES) {
            return 0;
        }
        found_hashed_symbol = 1;

        int terminated = 0;
        for (uint64_t step = 0U; step < URP_MAX_DYNAMIC_ENTRIES; ++step) {
            uint64_t chain_byte_offset;
            uint64_t chain_address;
            size_t chain_file_offset;
            if (symbol_index < first_hashed_symbol
                || symbol_index > URP_MAX_DYNAMIC_ENTRIES
                || !urp_checked_mul_u64(
                    symbol_index - first_hashed_symbol,
                    sizeof(uint32_t),
                    &chain_byte_offset)
                || !urp_checked_add_u64(chain_offset, chain_byte_offset, &chain_address)
                || !urp_find_load_range(
                    image,
                    image_size,
                    program_header_offset,
                    program_header_count,
                    chain_address,
                    sizeof(uint32_t),
                    0U,
                    1,
                    &chain_file_offset)) {
                return 0;
            }

            uint32_t chain = urp_read_u32_le(image + chain_file_offset);
            if (symbol_index > maximum_symbol_index) {
                maximum_symbol_index = symbol_index;
            }
            if (++total_chain_steps > URP_MAX_DYNAMIC_ENTRIES) {
                return 0;
            }
            if ((chain & 1U) != 0U) {
                terminated = 1;
                break;
            }
            if (symbol_index == UINT64_MAX) {
                return 0;
            }
            ++symbol_index;
        }
        if (terminated == 0) {
            return 0;
        }
    }

    if (!found_hashed_symbol) {
        *symbol_count_out = first_hashed_symbol;
        return 1;
    }
    if (!urp_checked_add_u64(maximum_symbol_index, 1U, symbol_count_out)
        || *symbol_count_out > URP_MAX_DYNAMIC_ENTRIES) {
        return 0;
    }
    return 1;
}

static int urp_dynamic_symbol_count(
    const uint8_t *image,
    size_t image_size,
    const urp_dynamic_values *dynamic,
    uint64_t program_header_offset,
    uint16_t program_header_count,
    uint64_t *symbol_count_out)
{
    if (!dynamic->has_gnu_hash) {
        return 0;
    }
    return urp_gnu_hash_symbol_count(
        image,
        image_size,
        dynamic->gnu_hash,
        program_header_offset,
        program_header_count,
        symbol_count_out);
}

/*
 * HostContext supports only import-side GNU version requirements attached to
 * its existing single-system-libc dependency slice. Versioned definitions
 * (and therefore versioned entry selection) remain outside the v1 contract.
 * The native loader resolves the checked libc requirements during RTLD_NOW.
 */
static urp_status urp_validate_symbol_version_needs(
    const uint8_t *image,
    size_t image_size,
    const urp_dynamic_values *dynamic,
    uint64_t program_header_offset,
    uint16_t program_header_count)
{
    int any_version_tags = dynamic->has_versym
        || dynamic->has_verneed || dynamic->has_verneednum;
    if (!any_version_tags) {
        return URP_STATUS_OK;
    }
    if (!dynamic->has_needed || !dynamic->has_versym
        || !dynamic->has_verneed || !dynamic->has_verneednum
        || dynamic->verneednum == 0U) {
        return URP_STATUS_UNSUPPORTED;
    }

    const char *needed_name;
    size_t needed_name_length;
    if (!urp_dynamic_string(
            image,
            image_size,
            dynamic,
            program_header_offset,
            program_header_count,
            dynamic->needed_offset,
            &needed_name,
            &needed_name_length)) {
        return URP_STATUS_LOAD_FAILED;
    }
    static const char glibc_soname[] = "libc.so.6";
    if (needed_name_length != sizeof(glibc_soname) - 1U
        || memcmp(needed_name, glibc_soname, sizeof(glibc_soname) - 1U) != 0) {
        return URP_STATUS_UNSUPPORTED;
    }
    if (dynamic->has_symbolic) {
        return URP_STATUS_UNSUPPORTED;
    }
    if (dynamic->has_sysv_hash) {
        return URP_STATUS_UNSUPPORTED;
    }

    uint64_t symbol_count;
    uint64_t version_table_size;
    if (dynamic->verneednum > URP_MAX_DYNAMIC_ENTRIES
        || dynamic->verneednum > (uint64_t)(image_size / 16U)
        || dynamic->verneednum > (uint64_t)SIZE_MAX
        || !urp_dynamic_symbol_count(
            image,
            image_size,
            dynamic,
            program_header_offset,
            program_header_count,
            &symbol_count)
        || !urp_checked_mul_u64(symbol_count, sizeof(uint16_t), &version_table_size)
        || version_table_size > (uint64_t)image_size
        || !urp_find_load_range(
            image,
            image_size,
            program_header_offset,
            program_header_count,
            dynamic->versym,
            version_table_size,
            0U,
            1,
            NULL)) {
        return URP_STATUS_LOAD_FAILED;
    }

    uint64_t version_need_address = dynamic->verneed;
    size_t total_auxiliary_count = 0U;
    size_t record_count = (size_t)dynamic->verneednum;
    for (size_t record_index = 0U; record_index < record_count; ++record_index) {
        size_t record_offset;
        if (!urp_find_load_range(
                image,
                image_size,
                program_header_offset,
                program_header_count,
                version_need_address,
                16U,
                0U,
                1,
                &record_offset)) {
            return URP_STATUS_LOAD_FAILED;
        }

        const uint8_t *record = image + record_offset;
        uint16_t version = urp_read_u16_le(record);
        uint16_t auxiliary_count = urp_read_u16_le(record + 2U);
        uint32_t file_name_offset = urp_read_u32_le(record + 4U);
        uint32_t auxiliary_relative_offset = urp_read_u32_le(record + 8U);
        uint32_t next_record_relative_offset = urp_read_u32_le(record + 12U);
        const char *file_name;
        size_t file_name_length;
        if (version != 1U || auxiliary_count == 0U
            || auxiliary_relative_offset < 16U
            || !urp_dynamic_string(
                image,
                image_size,
                dynamic,
                program_header_offset,
                program_header_count,
                file_name_offset,
                &file_name,
                &file_name_length)) {
            return URP_STATUS_LOAD_FAILED;
        }
        if (file_name_length != needed_name_length
            || memcmp(file_name, needed_name, needed_name_length) != 0) {
            return URP_STATUS_UNSUPPORTED;
        }

        uint64_t auxiliary_address;
        if (!urp_checked_add_u64(
                version_need_address,
                auxiliary_relative_offset,
                &auxiliary_address)) {
            return URP_STATUS_LOAD_FAILED;
        }
        for (uint16_t auxiliary_index = 0U;
            auxiliary_index < auxiliary_count;
            ++auxiliary_index) {
            size_t auxiliary_file_offset;
            if (!urp_find_load_range(
                    image,
                    image_size,
                    program_header_offset,
                    program_header_count,
                    auxiliary_address,
                    16U,
                    0U,
                    1,
                    &auxiliary_file_offset)) {
                return URP_STATUS_LOAD_FAILED;
            }

            const uint8_t *auxiliary = image + auxiliary_file_offset;
            uint32_t version_hash = urp_read_u32_le(auxiliary);
            uint16_t version_flags = urp_read_u16_le(auxiliary + 4U);
            uint16_t version_index = urp_read_u16_le(auxiliary + 6U);
            uint32_t name_offset = urp_read_u32_le(auxiliary + 8U);
            uint32_t next_auxiliary_relative_offset = urp_read_u32_le(auxiliary + 12U);
            const char *version_name;
            size_t version_name_length;
            if (!urp_dynamic_string(
                    image,
                    image_size,
                    dynamic,
                    program_header_offset,
                    program_header_count,
                    name_offset,
                    &version_name,
                    &version_name_length)
                || version_name_length == 0U) {
                return URP_STATUS_LOAD_FAILED;
            }
            if (version_flags != 0U) {
                return URP_STATUS_UNSUPPORTED;
            }
            if (version_index < 2U
                || (version_index & UINT16_C(0x8000)) != 0U
                || version_hash != urp_elf_name_hash(version_name, version_name_length)) {
                return URP_STATUS_LOAD_FAILED;
            }

            ++total_auxiliary_count;
            if (total_auxiliary_count > URP_MAX_DYNAMIC_ENTRIES
                || total_auxiliary_count > image_size / 16U) {
                return URP_STATUS_LOAD_FAILED;
            }
            if (auxiliary_index + 1U < auxiliary_count) {
                uint64_t next_auxiliary_address;
                if (next_auxiliary_relative_offset < 16U
                    || !urp_checked_add_u64(
                        auxiliary_address,
                        next_auxiliary_relative_offset,
                        &next_auxiliary_address)) {
                    return URP_STATUS_LOAD_FAILED;
                }
                auxiliary_address = next_auxiliary_address;
            } else if (next_auxiliary_relative_offset != 0U) {
                return URP_STATUS_LOAD_FAILED;
            }
        }

        uint64_t auxiliary_end_address;
        if (!urp_checked_add_u64(auxiliary_address, 16U, &auxiliary_end_address)) {
            return URP_STATUS_LOAD_FAILED;
        }
        if (record_index + 1U < record_count) {
            uint64_t next_record_address;
            if (next_record_relative_offset < 16U
                || !urp_checked_add_u64(
                    version_need_address,
                    next_record_relative_offset,
                    &next_record_address)
                || next_record_address < auxiliary_end_address) {
                return URP_STATUS_LOAD_FAILED;
            }
            version_need_address = next_record_address;
        } else if (next_record_relative_offset != 0U) {
            return URP_STATUS_LOAD_FAILED;
        }
    }

    return URP_STATUS_OK;
}

static urp_status urp_validate_relr(
    const uint8_t *image,
    size_t image_size,
    const urp_dynamic_values *dynamic,
    uint64_t program_header_offset,
    uint16_t program_header_count)
{
    if (!dynamic->has_relr && (dynamic->has_relrsz || dynamic->has_relrent)) {
        return URP_STATUS_LOAD_FAILED;
    }
    if (!dynamic->has_relr) {
        return URP_STATUS_OK;
    }
    if (!dynamic->has_relrsz || !dynamic->has_relrent
        || dynamic->relrent != sizeof(uint64_t)
        || dynamic->relrsz % dynamic->relrent != 0U) {
        return URP_STATUS_LOAD_FAILED;
    }

    size_t relr_offset;
    if (dynamic->relrsz > (uint64_t)SIZE_MAX
        || !urp_find_load_range(
            image,
            image_size,
            program_header_offset,
            program_header_count,
            dynamic->relr,
            dynamic->relrsz,
            0U,
            1,
            &relr_offset)) {
        return URP_STATUS_LOAD_FAILED;
    }

    const uint8_t *relr = image + relr_offset;
    size_t entry_count = (size_t)dynamic->relrsz / sizeof(uint64_t);
    uint64_t next = 0U;
    for (size_t index = 0; index < entry_count; ++index) {
        uint64_t entry = urp_read_u64_le(relr + index * sizeof(uint64_t));
        if ((entry & 1U) == 0U) {
            if (!urp_validate_relocation_target(
                    image,
                    image_size,
                    program_header_offset,
                    program_header_count,
                    entry)
                || !urp_checked_add_u64(entry, sizeof(uint64_t), &next)) {
                return URP_STATUS_UNSUPPORTED;
            }
            continue;
        }

        if (next == 0U) {
            return URP_STATUS_LOAD_FAILED;
        }
        for (uint32_t bit = 1U; bit < 64U; ++bit) {
            if ((entry & (UINT64_C(1) << bit)) == 0U) {
                continue;
            }
            uint64_t delta = (uint64_t)(bit - 1U) * sizeof(uint64_t);
            uint64_t target;
            if (!urp_checked_add_u64(next, delta, &target)
                || !urp_validate_relocation_target(
                    image,
                    image_size,
                    program_header_offset,
                    program_header_count,
                    target)) {
                return URP_STATUS_UNSUPPORTED;
            }
        }
        if (!urp_checked_add_u64(next, UINT64_C(63) * sizeof(uint64_t), &next)) {
            return URP_STATUS_UNSUPPORTED;
        }
    }
    return URP_STATUS_OK;
}

static urp_status urp_validate_dynamic_segment(
    const uint8_t *image,
    size_t image_size,
    uint64_t offset,
    uint64_t size,
    uint64_t program_header_offset,
    uint16_t program_header_count)
{
    size_t dynamic_offset;
    size_t dynamic_size;
    if (size == 0U
        || size % URP_ELF_DYNAMIC_ENTRY_SIZE != 0U
        || size / URP_ELF_DYNAMIC_ENTRY_SIZE > URP_MAX_DYNAMIC_ENTRIES
        || !urp_range_in_file(image_size, offset, size, &dynamic_offset, &dynamic_size)) {
        return URP_STATUS_LOAD_FAILED;
    }

    const uint8_t *dynamic = image + dynamic_offset;
    size_t entry_count = dynamic_size / URP_ELF_DYNAMIC_ENTRY_SIZE;
    urp_dynamic_values values = {0};
    size_t needed_count = 0U;
    int terminated = 0;
    for (size_t index = 0; index < entry_count; ++index) {
        const uint8_t *entry = dynamic + index * URP_ELF_DYNAMIC_ENTRY_SIZE;
        uint64_t tag = urp_read_u64_le(entry);
        if (tag == 0U) {
            terminated = 1;
            break;
        }

        switch (tag) {
        case URP_DT_NEEDED:
            /* P3 narrow slice: one system libc basename, no payload-controlled search path. */
            if (values.has_needed || needed_count++ != 0U) {
                return URP_STATUS_UNSUPPORTED;
            }
            values.needed_offset = urp_read_u64_le(entry + 8U);
            values.has_needed = 1;
            break;
        /* P3 bounded slice: the system loader owns constructor/destructor order; zero mutations remain rejected. */
        case URP_DT_INIT:
        case URP_DT_FINI:
        case URP_DT_INIT_ARRAY:
        case URP_DT_FINI_ARRAY:
        case URP_DT_INIT_ARRAYSZ:
        case URP_DT_FINI_ARRAYSZ:
        case URP_DT_PREINIT_ARRAY:
        case URP_DT_PREINIT_ARRAYSZ:
            /* The system loader defines constructor-before-entry and destructor-on-release. */
            if (urp_read_u64_le(entry + 8U) == 0U) {
                return URP_STATUS_UNSUPPORTED;
            }
            break;
        /* This narrow PLT slice uses the loader's ordinary preemptive lookup scope. */
        case URP_DT_SYMBOLIC:
            values.has_symbolic = 1;
            break;
        /* HostContext v1 defines no RPATH/RUNPATH search roots, ordering, or precedence. */
        case URP_DT_RPATH:
        case URP_DT_RUNPATH:
            return URP_STATUS_UNSUPPORTED;
        /* HostContext v1 defines no writable-text relocation or W^X semantics. */
        case URP_DT_TEXTREL:
            return URP_STATUS_UNSUPPORTED;
        /* HostContext v1 defines no auxiliary or filter dependency semantics. */
        case URP_DT_AUXILIARY:
        case URP_DT_FILTER:
            return URP_STATUS_UNSUPPORTED;
        /* runtime.host-context.unsupported-relocation-table: v1 defines only the checked AArch64 RELATIVE/RELR path. */
        case URP_DT_REL:
        case URP_DT_RELSZ:
        case URP_DT_RELENT:
            return URP_STATUS_UNSUPPORTED;
        /* HostContext v1 does not define Android packed relocation encodings. */
        case URP_DT_ANDROID_REL:
        case URP_DT_ANDROID_RELSZ:
        case URP_DT_ANDROID_RELA:
        case URP_DT_ANDROID_RELASZ:
        case URP_DT_ANDROID_RELR:
        case URP_DT_ANDROID_RELRSZ:
        case URP_DT_ANDROID_RELRENT:
        case URP_DT_ANDROID_RELRCOUNT:
            return URP_STATUS_UNSUPPORTED;
        /* Import-side version requirements are separately bounded below. */
        case URP_DT_VERSYM:
            if (values.has_versym) {
                return URP_STATUS_LOAD_FAILED;
            }
            values.versym = urp_read_u64_le(entry + 8U);
            values.has_versym = 1;
            values.has_version_tags = 1;
            break;
        /* Versioned definitions would make HostContext entry selection ambiguous. */
        case URP_DT_VERDEF:
        case URP_DT_VERDEFNUM:
            return URP_STATUS_UNSUPPORTED;
        case URP_DT_VERNEED:
            if (values.has_verneed) {
                return URP_STATUS_LOAD_FAILED;
            }
            values.verneed = urp_read_u64_le(entry + 8U);
            values.has_verneed = 1;
            values.has_version_tags = 1;
            break;
        case URP_DT_VERNEEDNUM:
            if (values.has_verneednum) {
                return URP_STATUS_LOAD_FAILED;
            }
            values.verneednum = urp_read_u64_le(entry + 8U);
            values.has_verneednum = 1;
            values.has_version_tags = 1;
            break;
        case URP_DT_HASH:
            if (values.has_sysv_hash) {
                return URP_STATUS_LOAD_FAILED;
            }
            values.has_sysv_hash = 1;
            break;
        case URP_DT_GNU_HASH:
            if (values.has_gnu_hash) {
                return URP_STATUS_LOAD_FAILED;
            }
            values.gnu_hash = urp_read_u64_le(entry + 8U);
            values.has_gnu_hash = 1;
            break;
        case URP_DT_FLAGS:
            if (values.has_flags
                || (urp_read_u64_le(entry + 8U) & ~URP_DF_BIND_NOW) != 0U) {
                return URP_STATUS_UNSUPPORTED;
            }
            values.flags = urp_read_u64_le(entry + 8U);
            values.has_flags = 1;
            break;
        case URP_DT_FLAGS_1:
            if (values.has_flags_1
                || (urp_read_u64_le(entry + 8U) & ~URP_DF_1_NOW) != 0U) {
                return URP_STATUS_UNSUPPORTED;
            }
            values.flags_1 = urp_read_u64_le(entry + 8U);
            values.has_flags_1 = 1;
            break;
        case URP_DT_RELA:
            if (values.has_rela) {
                return URP_STATUS_LOAD_FAILED;
            }
            values.rela = urp_read_u64_le(entry + 8U);
            values.has_rela = 1;
            break;
        case URP_DT_SYMTAB:
            if (values.has_symtab) {
                return URP_STATUS_LOAD_FAILED;
            }
            values.symtab = urp_read_u64_le(entry + 8U);
            values.has_symtab = 1;
            break;
        case URP_DT_SYMENT:
            if (values.has_syment) {
                return URP_STATUS_LOAD_FAILED;
            }
            values.syment = urp_read_u64_le(entry + 8U);
            values.has_syment = 1;
            break;
        case URP_DT_STRTAB:
            if (values.has_strtab) {
                return URP_STATUS_LOAD_FAILED;
            }
            values.strtab = urp_read_u64_le(entry + 8U);
            values.has_strtab = 1;
            break;
        case URP_DT_STRSZ:
            if (values.has_strsz) {
                return URP_STATUS_LOAD_FAILED;
            }
            values.strsz = urp_read_u64_le(entry + 8U);
            values.has_strsz = 1;
            break;
        case URP_DT_RELASZ:
            if (values.has_relasz) {
                return URP_STATUS_LOAD_FAILED;
            }
            values.relasz = urp_read_u64_le(entry + 8U);
            values.has_relasz = 1;
            break;
        case URP_DT_RELAENT:
            if (values.has_relaent) {
                return URP_STATUS_LOAD_FAILED;
            }
            values.relaent = urp_read_u64_le(entry + 8U);
            values.has_relaent = 1;
            break;
        case URP_DT_JMPREL:
            if (values.has_jmprel) {
                return URP_STATUS_LOAD_FAILED;
            }
            values.jmprel = urp_read_u64_le(entry + 8U);
            values.has_jmprel = 1;
            break;
        case URP_DT_PLTRELSZ:
            if (values.has_pltrelsz) {
                return URP_STATUS_LOAD_FAILED;
            }
            values.pltrelsz = urp_read_u64_le(entry + 8U);
            values.has_pltrelsz = 1;
            break;
        case URP_DT_PLTREL:
            if (values.has_pltrel) {
                return URP_STATUS_LOAD_FAILED;
            }
            values.pltrel = urp_read_u64_le(entry + 8U);
            values.has_pltrel = 1;
            break;
        case URP_DT_RELR:
            if (values.has_relr) {
                return URP_STATUS_LOAD_FAILED;
            }
            values.relr = urp_read_u64_le(entry + 8U);
            values.has_relr = 1;
            break;
        case URP_DT_RELRSZ:
            if (values.has_relrsz) {
                return URP_STATUS_LOAD_FAILED;
            }
            values.relrsz = urp_read_u64_le(entry + 8U);
            values.has_relrsz = 1;
            break;
        case URP_DT_RELRENT:
            if (values.has_relrent) {
                return URP_STATUS_LOAD_FAILED;
            }
            values.relrent = urp_read_u64_le(entry + 8U);
            values.has_relrent = 1;
            break;
        default:
            break;
        }
    }

    if (!terminated) {
        return URP_STATUS_LOAD_FAILED;
    }

    if (values.has_needed) {
        if (!values.has_strtab || !values.has_strsz
            || values.strsz == 0U
            || values.needed_offset >= values.strsz
            || values.strsz > (uint64_t)SIZE_MAX) {
            return URP_STATUS_LOAD_FAILED;
        }
        size_t string_offset;
        size_t string_size;
        if (!urp_find_load_range(
                image,
                image_size,
                program_header_offset,
                program_header_count,
                values.strtab,
                values.strsz,
                0U,
                1,
                &string_offset)
            || !urp_u64_to_size(values.strsz - values.needed_offset, &string_size)) {
            return URP_STATUS_LOAD_FAILED;
        }
        uint64_t needed_string_offset;
        if (!urp_checked_add_u64(
                (uint64_t)string_offset,
                values.needed_offset,
                &needed_string_offset)
            || needed_string_offset > (uint64_t)image_size
            || needed_string_offset > (uint64_t)SIZE_MAX) {
            return URP_STATUS_LOAD_FAILED;
        }
        const char *needed = (const char *)(image + (size_t)needed_string_offset);
        size_t max_length = string_size;
        size_t length = strnlen(needed, max_length);
        if (length == max_length
            || (strcmp(needed, "libc.so.6") != 0
                && strcmp(needed, "libc.so") != 0
                && strcmp(needed, "libc.musl-aarch64.so.1") != 0
                && strcmp(needed, "libc.so.1") != 0)) {
            return URP_STATUS_UNSUPPORTED;
        }
    }

    urp_status status = urp_validate_symbol_version_needs(
        image,
        image_size,
        &values,
        program_header_offset,
        program_header_count);
    if (status != URP_STATUS_OK) {
        return status;
    }
    status = urp_validate_rela(
        image,
        image_size,
        &values,
        program_header_offset,
        program_header_count);
    if (status != URP_STATUS_OK) {
        return status;
    }
    status = urp_validate_plt_rela(
        image,
        image_size,
        &values,
        program_header_offset,
        program_header_count);
    if (status != URP_STATUS_OK) {
        return status;
    }
    return urp_validate_relr(
        image,
        image_size,
        &values,
        program_header_offset,
        program_header_count);
}

urp_status urp_host_image_validate(const void *bytes, size_t image_size)
{
    const uint8_t *image = (const uint8_t *)bytes;
    if (image == NULL || image_size < URP_ELF_HEADER_SIZE) {
        return URP_STATUS_LOAD_FAILED;
    }

    static const uint8_t elf_magic[] = {0x7fU, 'E', 'L', 'F'};
    if (memcmp(image, elf_magic, sizeof(elf_magic)) != 0
        || image[4] != URP_ELF_CLASS_64
        || image[5] != URP_ELF_DATA_LSB
        || image[6] != URP_ELF_VERSION_CURRENT
        || urp_read_u16_le(image + 16U) != URP_ELF_TYPE_DYN
        || urp_read_u16_le(image + 18U) != URP_ELF_MACHINE_AARCH64
        || urp_read_u32_le(image + 20U) != URP_ELF_VERSION_CURRENT
        || urp_read_u16_le(image + 52U) != URP_ELF_HEADER_SIZE
        || urp_read_u16_le(image + 54U) != URP_ELF_PROGRAM_HEADER_SIZE) {
        return URP_STATUS_LOAD_FAILED;
    }

    uint64_t program_header_offset = urp_read_u64_le(image + 32U);
    uint16_t program_header_count = urp_read_u16_le(image + 56U);
    if (program_header_count == 0U || program_header_count > URP_MAX_PROGRAM_HEADERS) {
        return URP_STATUS_LOAD_FAILED;
    }

    uint64_t program_headers_size;
    if (!urp_checked_mul_u64(
            (uint64_t)program_header_count,
            URP_ELF_PROGRAM_HEADER_SIZE,
            &program_headers_size)
        || !urp_range_in_file(image_size, program_header_offset, program_headers_size, NULL, NULL)) {
        return URP_STATUS_LOAD_FAILED;
    }

    size_t load_count = 0U;
    int executable_load = 0;
    for (uint16_t index = 0; index < program_header_count; ++index) {
        uint64_t header_offset;
        if (!urp_checked_add_u64(
                program_header_offset,
                (uint64_t)index * URP_ELF_PROGRAM_HEADER_SIZE,
                &header_offset)) {
            return URP_STATUS_LOAD_FAILED;
        }
        const uint8_t *header = image + (size_t)header_offset;
        uint32_t type = urp_read_u32_le(header);
        uint32_t flags = urp_read_u32_le(header + 4U);
        uint64_t file_offset = urp_read_u64_le(header + 8U);
        uint64_t virtual_address = urp_read_u64_le(header + 16U);
        uint64_t file_size = urp_read_u64_le(header + 32U);
        uint64_t memory_size = urp_read_u64_le(header + 40U);
        uint64_t alignment = urp_read_u64_le(header + 48U);
        if (!urp_range_in_file(image_size, file_offset, file_size, NULL, NULL)
            || memory_size < file_size
            || !urp_is_power_of_two(alignment)
            || (alignment > 1U && file_offset % alignment != virtual_address % alignment)) {
            return URP_STATUS_LOAD_FAILED;
        }

        uint64_t virtual_end;
        if (!urp_checked_add_u64(virtual_address, memory_size, &virtual_end)) {
            return URP_STATUS_LOAD_FAILED;
        }

        switch (type) {
        case URP_PT_LOAD:
            ++load_count;
            if ((flags & URP_PF_X) != 0U && virtual_end > virtual_address) {
                executable_load = 1;
            }
            break;
        case URP_PT_DYNAMIC: {
            urp_status status = urp_validate_dynamic_segment(
                image,
                image_size,
                file_offset,
                file_size,
                program_header_offset,
                program_header_count);
            if (status != URP_STATUS_OK) {
                return status;
            }
            break;
        }
        case URP_PT_TLS:
            /* P4-A bounded slice: static initial-exec TLS is owned by the system loader. */
            if ((flags & URP_PF_X) != 0U
                || !urp_find_load_range(
                    image,
                    image_size,
                    program_header_offset,
                    program_header_count,
                    virtual_address,
                    memory_size,
                    URP_PF_W,
                    0,
                    NULL)) {
                return URP_STATUS_UNSUPPORTED;
            }
            break;
        case URP_PT_INTERP:
            return URP_STATUS_UNSUPPORTED;
        case URP_PT_GNU_PROPERTY:
            if ((flags & (URP_PF_W | URP_PF_X)) != 0U
                || urp_validate_gnu_property(image, image_size, file_offset, file_size)
                    != URP_STATUS_OK) {
                return URP_STATUS_UNSUPPORTED;
            }
            break;
        case URP_PT_GNU_STACK:
            if ((flags & URP_PF_X) != 0U) {
                return URP_STATUS_UNSUPPORTED;
            }
            break;
        default:
            break;
        }
    }

    if (load_count == 0U || !executable_load) {
        return URP_STATUS_LOAD_FAILED;
    }
    return URP_STATUS_OK;
}

