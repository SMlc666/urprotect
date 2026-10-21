#define _GNU_SOURCE

#include "host_image_validation.h"
#include "android_packed_relocation_tags.h"
#include "urp/host_adapter.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(URP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS)
#include <stdio.h>
#include <stdlib.h>
static void urp_trace_validation_failure(const char *stage, urp_status status)
{
    if (getenv("URP_HOST_VALIDATION_TRACE") != NULL) {
        (void)fprintf(stderr, "HostContext preflight %s returned %d\n", stage, status);
    }
}
#define URP_TRACE_VALIDATION_FAILURE(stage, status) \
    urp_trace_validation_failure((stage), (status))
#else
#define URP_TRACE_VALIDATION_FAILURE(stage, status) ((void)(stage), (void)(status))
#endif

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
#define URP_PT_NOTE 4U
#define URP_PT_TLS 7U
#define URP_PT_GNU_PROPERTY 0x6474e553U
#define URP_PT_GNU_STACK 0x6474e551U
#define URP_NOTE_GNU 5U
#define URP_GNU_PROPERTY_AARCH64_FEATURE_1_AND UINT32_C(0xC0000000)
#define URP_GNU_PROPERTY_AARCH64_FEATURE_1_BTI UINT32_C(1)
#define URP_GNU_PROPERTY_AARCH64_FEATURE_1_PAC UINT32_C(2)
#define URP_PF_X 1U
#define URP_PF_W 2U
#define URP_PF_R 4U
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
#define URP_R_AARCH64_TLS_DTPMOD64 1028U
#define URP_R_AARCH64_TLS_DTPREL64 1029U
#define URP_R_AARCH64_TLSDESC 1031U
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
#define URP_DT_VERSYM UINT64_C(0x6ffffff0)
#define URP_DT_GNU_HASH UINT64_C(0x6ffffef5)
#define URP_DT_VERDEF UINT64_C(0x6ffffffc)
#define URP_DT_VERDEFNUM UINT64_C(0x6ffffffd)
#define URP_DT_VERNEED UINT64_C(0x6ffffffe)
#define URP_DT_VERNEEDNUM UINT64_C(0x6fffffff)
#define URP_DT_FLAGS_1 UINT64_C(0x6ffffffb)
#define URP_DT_AUDIT UINT64_C(0x6ffffefc)
#define URP_DT_DEPAUDIT UINT64_C(0x6ffffefb)
#define URP_DT_CONFIG UINT64_C(0x6ffffefa)
#define URP_DT_AUXILIARY UINT64_C(0x7ffffffd)
#define URP_DT_FILTER UINT64_C(0x7fffffff)
#define URP_DF_BIND_NOW UINT64_C(0x8)
#define URP_DF_1_NOW UINT64_C(0x1)
#define URP_STB_GLOBAL 1U
#define URP_STB_WEAK 2U
#define URP_STT_OBJECT 1U
#define URP_STT_FUNC 2U
#define URP_STT_TLS 6U
#define URP_STV_DEFAULT 0U
#define URP_STV_PROTECTED 3U
#define URP_SHN_UNDEF 0U
#define URP_R_AARCH64_RELATIVE 1027U
#define URP_MAX_PROGRAM_HEADERS 4096U
#define URP_MAX_DYNAMIC_ENTRIES (1U << 20)
#define URP_PROVIDER_AGGREGATE_WORK_BUDGET (UINT64_C(8) * 1024U * 1024U)

#if defined(URP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS)
typedef enum urp_provider_work_diagnostic_scope {
    URP_PROVIDER_WORK_DIAGNOSTICS_NONE = 0,
    URP_PROVIDER_WORK_DIAGNOSTICS_CANDIDATE,
    URP_PROVIDER_WORK_DIAGNOSTICS_PROVIDER_PARSE,
} urp_provider_work_diagnostic_scope;
#endif

typedef struct urp_provider_work {
    uint64_t limit;
    uint64_t used;
#if defined(URP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS)
    urp_provider_work_diagnostic_scope diagnostic_scope;
#endif
} urp_provider_work;

typedef struct urp_provider_load_range {
    uint64_t virtual_address;
    uint64_t file_offset;
    uint64_t file_size;
    uint32_t flags;
} urp_provider_load_range;

typedef struct urp_provider_load_index {
    urp_provider_load_range ranges[URP_MAX_PROGRAM_HEADERS];
    size_t count;
} urp_provider_load_index;

#if defined(URP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS)
/* Consumer counters describe the latest validation call; parser counters describe the latest
 * provider parse.
 */
static uint64_t urp_provider_test_work_limit = URP_PROVIDER_AGGREGATE_WORK_BUDGET;
static uint64_t urp_provider_test_candidate_work_used;
static uint64_t urp_provider_test_candidate_dynamic_entries;
static uint64_t urp_provider_test_candidate_range_work;
static uint64_t urp_provider_test_candidate_needed_string_bytes;
static uint64_t urp_provider_test_consumer_rela_validation_count;
static uint64_t urp_provider_test_symbol_version_validation_count;
static uint64_t urp_provider_test_provider_parse_work_used;
static uint64_t urp_provider_test_provider_parse_count;

void urp_host_image_validation_test_set_provider_work_limit(uint64_t limit)
{
    urp_provider_test_work_limit = limit;
}

uint64_t urp_host_image_validation_test_provider_candidate_work_used(void)
{
    return urp_provider_test_candidate_work_used;
}

uint64_t urp_host_image_validation_test_provider_candidate_dynamic_entries(void)
{
    return urp_provider_test_candidate_dynamic_entries;
}

uint64_t urp_host_image_validation_test_provider_candidate_range_work(void)
{
    return urp_provider_test_candidate_range_work;
}

uint64_t urp_host_image_validation_test_provider_candidate_needed_string_bytes(void)
{
    return urp_provider_test_candidate_needed_string_bytes;
}

uint64_t urp_host_image_validation_test_consumer_rela_validation_count(void)
{
    return urp_provider_test_consumer_rela_validation_count;
}

uint64_t urp_host_image_validation_test_symbol_version_validation_count(void)
{
    return urp_provider_test_symbol_version_validation_count;
}

uint64_t urp_host_image_validation_test_provider_parse_work_used(void)
{
    return urp_provider_test_provider_parse_work_used;
}

uint64_t urp_host_image_validation_test_provider_parse_count(void)
{
    return urp_provider_test_provider_parse_count;
}
#endif

typedef struct urp_dynamic_values {
    uint64_t strtab;
    uint64_t strsz;
    uint64_t needed_offsets[2];
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
    size_t needed_count;
    int has_sysv_hash;
    int has_gnu_hash;
    int has_versym;
    int has_verneed;
    int has_verneednum;
    int has_verdef;
    int has_verdefnum;
    int duplicate_version_tags;
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
    int provider_dependency;
    uint64_t provider_got_address;
    urp_provider_work *candidate_work;
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
static int urp_get_program_header(
    const uint8_t *image,
    size_t image_size,
    uint64_t program_header_offset,
    uint16_t program_header_count,
    uint16_t index,
    const uint8_t **header_out);

static int urp_provider_work_take(urp_provider_work *work, uint64_t amount)
{
    if (work == NULL || work->used > work->limit
        || amount > work->limit - work->used) return 0;
    work->used += amount;
#if defined(URP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS)
    if (work->diagnostic_scope == URP_PROVIDER_WORK_DIAGNOSTICS_CANDIDATE) {
        urp_provider_test_candidate_work_used = work->used;
    } else if (work->diagnostic_scope == URP_PROVIDER_WORK_DIAGNOSTICS_PROVIDER_PARSE) {
        urp_provider_test_provider_parse_work_used = work->used;
    }
#endif
    return 1;
}

static int urp_provider_work_take_dynamic_entries(urp_provider_work *work, uint64_t amount)
{
    if (!urp_provider_work_take(work, amount)) return 0;
#if defined(URP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS)
    if (work->diagnostic_scope == URP_PROVIDER_WORK_DIAGNOSTICS_CANDIDATE) {
        urp_provider_test_candidate_dynamic_entries += amount;
    }
#endif
    return 1;
}

static uint64_t urp_provider_work_limit(void)
{
#if defined(URP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS)
    return urp_provider_test_work_limit;
#else
    return URP_PROVIDER_AGGREGATE_WORK_BUDGET;
#endif
}

static int urp_provider_build_load_index(
    const uint8_t *image,
    size_t image_size,
    uint64_t program_header_offset,
    uint16_t program_header_count,
    urp_provider_work *work,
    urp_provider_load_index *index)
{
    if (index == NULL || program_header_count == 0U
        || program_header_count > URP_MAX_PROGRAM_HEADERS
        || !urp_provider_work_take(work, program_header_count)) return 0;
    index->count = 0U;
    for (uint16_t position = 0U; position < program_header_count; ++position) {
        const uint8_t *header;
        if (!urp_get_program_header(
                image, image_size, program_header_offset, program_header_count,
                position, &header)) return 0;
        if (urp_read_u32_le(header) != URP_PT_LOAD) continue;
        if (index->count >= URP_MAX_PROGRAM_HEADERS) return 0;
        urp_provider_load_range *range = &index->ranges[index->count++];
        range->flags = urp_read_u32_le(header + 4U);
        range->file_offset = urp_read_u64_le(header + 8U);
        range->virtual_address = urp_read_u64_le(header + 16U);
        range->file_size = urp_read_u64_le(header + 32U);
    }
    return index->count != 0U;
}

static int urp_provider_find_load_range(
    const uint8_t *image,
    size_t image_size,
    const urp_provider_load_index *index,
    urp_provider_work *work,
    uint64_t virtual_address,
    uint64_t length,
    uint32_t required_flags,
    uint32_t forbidden_flags,
    size_t *file_offset_out,
    uint64_t *available_bytes_out)
{
    (void)image;
    if (index == NULL || index->count == 0U
        || !urp_provider_work_take(work, (uint64_t)index->count)) return 0;
    size_t matches = 0U;
    size_t selected_offset = 0U;
    uint64_t selected_available = 0U;
    for (size_t position = 0U; position < index->count; ++position) {
        const urp_provider_load_range *range = &index->ranges[position];
        if ((range->flags & required_flags) != required_flags
            || (range->flags & forbidden_flags) != 0U
            || virtual_address < range->virtual_address) continue;
        uint64_t delta = virtual_address - range->virtual_address;
        if (delta > range->file_size || length > range->file_size - delta) continue;
        uint64_t file_offset;
        size_t resolved_offset;
        if (!urp_checked_add_u64(range->file_offset, delta, &file_offset)
            || !urp_range_in_file(image_size, file_offset, length, &resolved_offset, NULL)) return 0;
        selected_offset = resolved_offset;
        selected_available = range->file_size - delta;
        if (++matches > 1U) return 0;
    }
    if (matches != 1U) return 0;
#if defined(URP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS)
    if (work->diagnostic_scope == URP_PROVIDER_WORK_DIAGNOSTICS_CANDIDATE) {
        urp_provider_test_candidate_range_work += (uint64_t)index->count;
    }
#endif
    if (file_offset_out != NULL) *file_offset_out = selected_offset;
    if (available_bytes_out != NULL) *available_bytes_out = selected_available;
    return 1;
}

static int urp_provider_string(
    const uint8_t *image,
    size_t string_table_offset,
    size_t string_table_size,
    uint64_t string_offset,
    urp_provider_work *work,
    const char **string_out,
    size_t *string_length_out)
{
    if (string_offset >= (uint64_t)string_table_size
        || string_offset > (uint64_t)SIZE_MAX) return 0;
    size_t relative = (size_t)string_offset;
    size_t remaining = string_table_size - relative;
    for (size_t length = 0U; length < remaining; ++length) {
        if (!urp_provider_work_take(work, 1U)) return 0;
        if (image[string_table_offset + relative + length] == 0U) {
            if (string_out != NULL) {
                *string_out = (const char *)(image + string_table_offset + relative);
            }
            if (string_length_out != NULL) *string_length_out = length;
            return 1;
        }
    }
    return 0;
}

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
    size_t *file_offset_out,
    urp_provider_work *work)
{
    if (work != NULL) {
        if (!urp_provider_work_take(work, program_header_count)) return 0;
#if defined(URP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS)
        if (work->diagnostic_scope == URP_PROVIDER_WORK_DIAGNOSTICS_CANDIDATE) {
            urp_provider_test_candidate_range_work += program_header_count;
        }
#endif
    }
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

static int urp_find_tls_owner(
    const uint8_t *image,
    size_t image_size,
    uint64_t program_header_offset,
    uint16_t program_header_count,
    uint64_t tls_file_offset,
    uint64_t tls_virtual_address,
    uint64_t tls_file_size,
    uint64_t tls_memory_size,
    uint32_t tls_flags,
    urp_provider_work *work)
{
    size_t owner_count = 0U;
    if (work != NULL && !urp_provider_work_take(work, program_header_count)) return 0;
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

        if (urp_read_u32_le(header) != URP_PT_LOAD) {
            continue;
        }

        uint32_t load_flags = urp_read_u32_le(header + 4U);
        uint64_t load_file_offset = urp_read_u64_le(header + 8U);
        uint64_t load_virtual_address = urp_read_u64_le(header + 16U);
        uint64_t load_file_size = urp_read_u64_le(header + 32U);
        uint64_t load_memory_size = urp_read_u64_le(header + 40U);
        if ((load_flags & (URP_PF_R | URP_PF_W)) != (URP_PF_R | URP_PF_W)
            || tls_virtual_address < load_virtual_address
            || tls_memory_size > load_memory_size
            || tls_virtual_address - load_virtual_address
                > load_memory_size - tls_memory_size) {
            continue;
        }

        uint64_t virtual_delta = tls_virtual_address - load_virtual_address;
        if (tls_file_size != 0U) {
            if (tls_file_offset < load_file_offset
                || tls_file_size > load_file_size
                || tls_file_offset - load_file_offset != virtual_delta
                || tls_file_offset - load_file_offset > load_file_size - tls_file_size) {
                continue;
            }
        }

        if ((tls_flags & URP_PF_W) != 0U && (load_flags & URP_PF_W) == 0U) {
            continue;
        }
        if (++owner_count > 1U) {
            return 0;
        }
    }

    return owner_count == 1U;
}

static int urp_get_tls_memory_size(
    const uint8_t *image,
    size_t image_size,
    uint64_t program_header_offset,
    uint16_t program_header_count,
    uint64_t *memory_size_out,
    urp_provider_work *work)
{
    size_t tls_count = 0U;
    uint64_t memory_size = 0U;
    if (work != NULL && !urp_provider_work_take(work, program_header_count)) return 0;
    for (uint16_t index = 0U; index < program_header_count; ++index) {
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
        if (urp_read_u32_le(header) != URP_PT_TLS) {
            continue;
        }

        uint64_t file_offset = urp_read_u64_le(header + 8U);
        uint64_t virtual_address = urp_read_u64_le(header + 16U);
        uint64_t file_size = urp_read_u64_le(header + 32U);
        uint64_t segment_memory_size = urp_read_u64_le(header + 40U);
        uint32_t flags = urp_read_u32_le(header + 4U);
        if (++tls_count != 1U
            || segment_memory_size == 0U
            || file_size > segment_memory_size
            || !urp_range_in_file(image_size, file_offset, file_size, NULL, NULL)
            || !urp_find_tls_owner(
                image,
                image_size,
                program_header_offset,
                program_header_count,
                file_offset,
                virtual_address,
                file_size,
                segment_memory_size,
                flags,
                work)) {
            return 0;
        }
        memory_size = segment_memory_size;
    }

    if (tls_count != 1U) {
        return 0;
    }
    if (memory_size_out != NULL) {
        *memory_size_out = memory_size;
    }
    return 1;
}

/* In AArch64 ELF64 ET_DYN images, STT_TLS st_value is a TLS-block-relative
 * offset, not a link-time virtual address. Do not reinterpret VA-shaped values
 * as offsets: that would silently broaden the loader metadata contract. */
static int urp_tls_symbol_value_in_bounds(
    uint64_t symbol_value,
    uint64_t symbol_size,
    uint64_t tls_memory_size)
{
    return symbol_value <= tls_memory_size
        && symbol_size <= tls_memory_size - symbol_value;
}

static int urp_validate_relocation_target(
    const uint8_t *image,
    size_t image_size,
    uint64_t program_header_offset,
    uint16_t program_header_count,
    uint64_t target,
    urp_provider_work *work)
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
        NULL,
        work);
}

static int urp_validate_defined_tls_symbol(
    const uint8_t *image,
    size_t image_size,
    const urp_dynamic_values *dynamic,
    uint64_t program_header_offset,
    uint16_t program_header_count,
    const uint8_t *relocation,
    uint64_t symbol)
{
    uint64_t symbol_delta;
    uint64_t symbol_address;
    size_t symbol_offset;
    if (!dynamic->has_symtab
        || !dynamic->has_syment
        || dynamic->syment != 24U
        || symbol == 0U
        || !urp_checked_mul_u64(symbol, dynamic->syment, &symbol_delta)
        || !urp_checked_add_u64(dynamic->symtab, symbol_delta, &symbol_address)
        || !urp_find_load_range(
            image,
            image_size,
            program_header_offset,
            program_header_count,
            symbol_address,
            dynamic->syment,
            0U,
            1,
            &symbol_offset,
            dynamic->candidate_work)) {
        return 0;
    }

    const uint8_t *symbol_record = image + symbol_offset;
    uint64_t symbol_value = urp_read_u64_le(symbol_record + 8U);
    uint64_t symbol_size = urp_read_u64_le(symbol_record + 16U);
    uint8_t symbol_info = symbol_record[4U];
    uint8_t symbol_type = (uint8_t)(symbol_info & 0x0fU);
    uint8_t symbol_binding = (uint8_t)(symbol_info >> 4U);
    uint16_t section_index = urp_read_u16_le(symbol_record + 6U);
    uint64_t tls_memory_size = 0U;
    if (symbol_type != URP_STT_TLS
        || (symbol_binding != 0U
            && symbol_binding != URP_STB_GLOBAL
            && symbol_binding != URP_STB_WEAK)
        || section_index == URP_SHN_UNDEF
        || !urp_get_tls_memory_size(
            image,
            image_size,
            program_header_offset,
            program_header_count,
            &tls_memory_size,
            dynamic->candidate_work)
        || !urp_tls_symbol_value_in_bounds(symbol_value, symbol_size, tls_memory_size)) {
#if defined(URP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS)
        if (getenv("URP_HOST_VALIDATION_TRACE") != NULL) {
            (void)fprintf(stderr,
                "TLS symbol rejected type=%u binding=%u section=%u "
                "value=%llu size=%llu memorySize=%llu symindex=%llu\\n",
                (unsigned)symbol_type, (unsigned)symbol_binding, (unsigned)section_index,
                (unsigned long long)symbol_value, (unsigned long long)symbol_size,
                (unsigned long long)tls_memory_size, (unsigned long long)symbol);
        }
#endif
        return 0;
    }

    uint64_t addend_bits = urp_read_u64_le(relocation + 16U);
    int addend_valid = ((addend_bits >> 63U) == 0U)
        ? addend_bits <= tls_memory_size - symbol_value
        : ((~addend_bits) + 1U) <= symbol_value;
#if defined(URP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS)
    if (!addend_valid && getenv("URP_HOST_VALIDATION_TRACE") != NULL) {
        (void)fprintf(stderr,
            "TLS relocation addend rejected symbol=%llu value=%llu size=%llu "
            "memorySize=%llu addend=0x%llx\\n",
            (unsigned long long)symbol, (unsigned long long)symbol_value,
            (unsigned long long)symbol_size, (unsigned long long)tls_memory_size,
            (unsigned long long)addend_bits);
    }
#endif
    return addend_valid;
}

static int urp_dynamic_string(
    const uint8_t *image,
    size_t image_size,
    const urp_dynamic_values *dynamic,
    uint64_t program_header_offset,
    uint16_t program_header_count,
    uint64_t string_offset,
    const char **string_out,
    size_t *string_length_out);

static int urp_dynamic_symbol_count(
    const uint8_t *image,
    size_t image_size,
    const urp_dynamic_values *dynamic,
    uint64_t program_header_offset,
    uint16_t program_header_count,
    uint64_t *symbol_count_out);
static int urp_provider_gnu_hash_symbol_count(
    const uint8_t *image,
    size_t image_size,
    uint64_t hash_address,
    const urp_provider_load_index *load_index,
    urp_provider_work *work,
    uint64_t *symbol_count_out);

static urp_status urp_validate_rela_table(
    const uint8_t *image,
    size_t image_size,
    urp_dynamic_values *dynamic,
    uint64_t rela_address,
    uint64_t rela_size,
    uint64_t program_header_offset,
    uint16_t program_header_count)
{
    if (rela_size == 0U || rela_size % 24U != 0U) {
        return URP_STATUS_LOAD_FAILED;
    }

    urp_provider_work *work = dynamic->candidate_work;
    urp_provider_work legacy_work = {
        .limit = URP_PROVIDER_AGGREGATE_WORK_BUDGET,
        .used = 0U,
#if defined(URP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS)
        .diagnostic_scope = URP_PROVIDER_WORK_DIAGNOSTICS_NONE,
#endif
    };
    size_t entry_count = (size_t)(rela_size / 24U);
#if defined(URP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS)
    if (dynamic->provider_dependency) {
        ++urp_provider_test_consumer_rela_validation_count;
    }
#endif
    if (work != NULL && !urp_provider_work_take(work, (uint64_t)entry_count)) {
        return URP_STATUS_UNSUPPORTED;
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
            &rela_offset,
            work)) {
        return URP_STATUS_LOAD_FAILED;
    }

    const uint8_t *rela = image + rela_offset;
    if (dynamic->provider_dependency) {
        if (entry_count != 1U || rela_size != 24U
            || dynamic->needed_count != 1U
            || !dynamic->has_symtab || !dynamic->has_syment || dynamic->syment != 24U
            || !dynamic->has_strtab || !dynamic->has_strsz
            || dynamic->strsz == 0U || dynamic->strsz > (uint64_t)SIZE_MAX
            || dynamic->has_version_tags || dynamic->has_symbolic
            || dynamic->has_jmprel || dynamic->has_relr
            || !dynamic->has_gnu_hash) {
            return URP_STATUS_UNSUPPORTED;
        }
        urp_provider_load_index load_index;
        if (!urp_provider_build_load_index(
                image, image_size, program_header_offset, program_header_count,
                work, &load_index)) return URP_STATUS_UNSUPPORTED;
        size_t string_table_offset;
        if (!urp_provider_find_load_range(
                image, image_size, &load_index, work,
                dynamic->strtab, dynamic->strsz, 0U, 0U,
                &string_table_offset, NULL)) return URP_STATUS_UNSUPPORTED;
        const uint8_t *string_table = image + string_table_offset;
        size_t string_table_size = (size_t)dynamic->strsz;
        if (string_table[0] != 0U || string_table[string_table_size - 1U] != 0U) {
            return URP_STATUS_UNSUPPORTED;
        }

        const uint8_t *entry = rela;
        uint64_t target = urp_read_u64_le(entry);
        uint64_t info = urp_read_u64_le(entry + 8U);
        uint32_t type = (uint32_t)info;
        uint64_t symbol = info >> 32U;
        uint64_t symbol_delta;
        uint64_t symbol_address;
        size_t symbol_offset;
        size_t got_offset;
        if (type != URP_R_AARCH64_GLOB_DAT || symbol == 0U
            || urp_read_u64_le(entry + 16U) != 0U
            || !urp_checked_mul_u64(symbol, dynamic->syment, &symbol_delta)
            || !urp_checked_add_u64(dynamic->symtab, symbol_delta, &symbol_address)
            || !urp_provider_find_load_range(
                image, image_size, &load_index, work,
                symbol_address, dynamic->syment, 0U, 0U, &symbol_offset, NULL)
            || target % sizeof(uint64_t) != 0U
            || !urp_provider_find_load_range(
                image, image_size, &load_index, work,
                target, sizeof(uint64_t), URP_PF_W, 0U, &got_offset, NULL)) {
            return URP_STATUS_UNSUPPORTED;
        }
        (void)got_offset;
        const uint8_t *symbol_record = image + symbol_offset;
        uint64_t name_offset = urp_read_u32_le(symbol_record);
        size_t required_name_length = sizeof(URP_HOST_EXTERNAL_TABLE_SYMBOL) - 1U;
        uint8_t symbol_info = symbol_record[4U];
        uint8_t symbol_other = symbol_record[5U];
        uint16_t symbol_section = urp_read_u16_le(symbol_record + 6U);
        if (name_offset >= (uint64_t)string_table_size
            || required_name_length >= string_table_size - (size_t)name_offset
            || memcmp(string_table + (size_t)name_offset,
                URP_HOST_EXTERNAL_TABLE_SYMBOL, required_name_length) != 0
            || string_table[(size_t)name_offset + required_name_length] != 0U
            || (symbol_info >> 4U) != URP_STB_GLOBAL
            || (symbol_info & 0x0fU) != URP_STT_OBJECT
            || symbol_other != URP_STV_DEFAULT
            || symbol_section != URP_SHN_UNDEF
            || urp_read_u64_le(symbol_record + 8U) != 0U
            /* GNU ld emits st_size 0 for this undefined object import. */
            || (urp_read_u64_le(symbol_record + 16U) != 0U
                && urp_read_u64_le(symbol_record + 16U) != 16U)) {
            return URP_STATUS_UNSUPPORTED;
        }

        uint64_t symbol_count;
        uint64_t symbol_table_size;
        size_t symbol_table_offset;
        uint64_t string_scan_cost;
        if (!urp_provider_gnu_hash_symbol_count(
                image, image_size, dynamic->gnu_hash, &load_index,
                work, &symbol_count)
            || symbol_count == 0U || symbol_count > URP_MAX_DYNAMIC_ENTRIES
            || symbol >= symbol_count
            || !urp_checked_mul_u64(symbol_count, dynamic->syment, &symbol_table_size)
            || !urp_provider_find_load_range(
                image, image_size, &load_index, work,
                dynamic->symtab, symbol_table_size, 0U, 0U,
                &symbol_table_offset, NULL)
            || !urp_checked_mul_u64(
                symbol_count, required_name_length + 1U, &string_scan_cost)
            || !urp_provider_work_take(work, symbol_count)
            || !urp_provider_work_take(work, string_scan_cost)) {
            return URP_STATUS_UNSUPPORTED;
        }
        size_t named_provider_symbols = 0U;
        for (uint64_t index = 0U; index < symbol_count; ++index) {
            size_t row_offset = symbol_table_offset + (size_t)(index * dynamic->syment);
            const uint8_t *row = image + row_offset;
            uint64_t name = urp_read_u32_le(row);
            if (name >= (uint64_t)string_table_size) return URP_STATUS_UNSUPPORTED;
            size_t name_index = (size_t)name;
            if (string_table[name_index] == (uint8_t)URP_HOST_EXTERNAL_TABLE_SYMBOL[0]
                && required_name_length < string_table_size - name_index
                && memcmp(string_table + name_index,
                    URP_HOST_EXTERNAL_TABLE_SYMBOL, required_name_length) == 0
                && string_table[name_index + required_name_length] == 0U) {
                ++named_provider_symbols;
                if (index != symbol) return URP_STATUS_UNSUPPORTED;
            }
        }
        if (named_provider_symbols != 1U) return URP_STATUS_UNSUPPORTED;
        dynamic->provider_got_address = target;
        return URP_STATUS_OK;
    }

    size_t import_string_table_offset = 0U;
    int import_string_table_indexed = 0;
    for (size_t index = 0; index < entry_count; ++index) {
        const uint8_t *entry = rela + index * 24U;
        uint64_t offset = urp_read_u64_le(entry);
        uint64_t info = urp_read_u64_le(entry + 8U);
        uint32_t type = (uint32_t)info;
        uint64_t symbol = info >> 32U;
        int dynamic_tls = type == URP_R_AARCH64_TLS_DTPMOD64
            || type == URP_R_AARCH64_TLS_DTPREL64;
        int symbolic = type == URP_R_AARCH64_ABS64
            || type == URP_R_AARCH64_GLOB_DAT
            || type == URP_R_AARCH64_TLS_TPREL64;
        uint64_t symbol_delta = 0U;
        uint64_t symbol_address = 0U;
        size_t symbol_file_offset = 0U;
        int symbol_range_valid = 1;
        if (symbolic) {
            if (work == NULL && type == URP_R_AARCH64_GLOB_DAT
                && !urp_provider_work_take(&legacy_work, program_header_count)) {
                return URP_STATUS_UNSUPPORTED;
            }
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
                    type == URP_R_AARCH64_GLOB_DAT ? &symbol_file_offset : NULL,
                    work);
            if (symbol_range_valid && type == URP_R_AARCH64_GLOB_DAT) {
                if (!dynamic->has_strtab || !dynamic->has_strsz
                    || dynamic->strsz == 0U || dynamic->strsz > (uint64_t)SIZE_MAX) {
                    return URP_STATUS_UNSUPPORTED;
                }
                if (!import_string_table_indexed) {
                    if ((work == NULL
                            && !urp_provider_work_take(&legacy_work, program_header_count))
                        || !urp_find_load_range(
                            image, image_size, program_header_offset, program_header_count,
                            dynamic->strtab, dynamic->strsz, 0U, 1,
                            &import_string_table_offset, work)) {
                        return URP_STATUS_UNSUPPORTED;
                    }
                    import_string_table_indexed = 1;
                }
                uint64_t name_offset = urp_read_u32_le(image + symbol_file_offset);
                urp_provider_work *string_work = work != NULL ? work : &legacy_work;
                if (name_offset >= dynamic->strsz
                    || !urp_provider_work_take(string_work, 1U)) {
                    return URP_STATUS_UNSUPPORTED;
                }
                size_t name_index = (size_t)name_offset;
                const uint8_t *name = image + import_string_table_offset + name_index;
                size_t provider_name_length = sizeof(URP_HOST_EXTERNAL_TABLE_SYMBOL) - 1U;
                if (name[0] == (uint8_t)URP_HOST_EXTERNAL_TABLE_SYMBOL[0]) {
                    if (!urp_provider_work_take(string_work, provider_name_length + 1U)) {
                        return URP_STATUS_UNSUPPORTED;
                    }
                    if (provider_name_length < (size_t)dynamic->strsz - name_index
                        && memcmp(name, URP_HOST_EXTERNAL_TABLE_SYMBOL, provider_name_length) == 0
                        && name[provider_name_length] == 0U) {
                        /* A provider import is authorized only by its exact DT_NEEDED. */
                        return URP_STATUS_UNSUPPORTED;
                    }
                }
            }
            if (symbol_range_valid && type == URP_R_AARCH64_TLS_TPREL64) {
                symbol_range_valid = urp_validate_defined_tls_symbol(
                    image,
                    image_size,
                    dynamic,
                    program_header_offset,
                    program_header_count,
                    entry,
                    symbol);
            }
        }
        if (dynamic_tls) {
            /*
             * The dynamic TLS ABI has two distinct loader-owned forms in this
             * table. DTPMOD64 owns a module-id slot and therefore has no
             * symbol-table owner; DTPREL64 names a defined TLS symbol. Both
             * targets are eight-byte writable image locations. Keep this
             * contract separate from TPREL64 so an arbitrary TLS relocation
             * cannot enter the accepted subset by type confusion.
             */
            if (type == URP_R_AARCH64_TLS_DTPMOD64) {
                uint64_t tls_memory_size = 0U;
                symbol_range_valid = urp_get_tls_memory_size(
                        image,
                        image_size,
                        program_header_offset,
                        program_header_count,
                        &tls_memory_size,
                        work)
                    && urp_read_u64_le(entry + 16U) == 0U
                    && (symbol == 0U
                        || urp_validate_defined_tls_symbol(
                            image,
                            image_size,
                            dynamic,
                            program_header_offset,
                            program_header_count,
                            entry,
                            symbol));
            } else {
                symbol_range_valid = urp_validate_defined_tls_symbol(
                    image,
                    image_size,
                    dynamic,
                    program_header_offset,
                    program_header_count,
                    entry,
                    symbol);
            }
        }
        int target_valid = type == 0U
            || urp_validate_relocation_target(
                image,
                image_size,
                program_header_offset,
                program_header_count,
                offset,
                work);
        if ((type != 0U && type != URP_R_AARCH64_RELATIVE && !symbolic && !dynamic_tls)
            || (type == 0U && symbol != 0U)
            || (type == URP_R_AARCH64_RELATIVE && symbol != 0U)
            || ((symbolic || dynamic_tls) && !symbol_range_valid)
            || (type != 0U && !target_valid)) {
#if defined(URP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS)
            if (getenv("URP_HOST_VALIDATION_TRACE") != NULL) {
                (void)fprintf(
                    stderr,
                    "RELA detail type=%u offset=0x%llx symbol=%llu symbolic=%d dynamic_tls=%d symbol_valid=%d target_valid=%d\\n",
                    type,
                    (unsigned long long)offset,
                    (unsigned long long)symbol,
                    symbolic,
                    dynamic_tls,
                    symbol_range_valid,
                    target_valid);
            }
#endif
            return URP_STATUS_UNSUPPORTED;
        }
    }
    return URP_STATUS_OK;
}

static urp_status urp_validate_rela(
    const uint8_t *image,
    size_t image_size,
    urp_dynamic_values *dynamic,
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
        || (dynamic->has_relaent && dynamic->relaent != 24U)
        || !dynamic->has_symtab || !dynamic->has_syment
        || dynamic->syment != 24U
        || !((dynamic->has_flags && (dynamic->flags & URP_DF_BIND_NOW) != 0U)
            || (dynamic->has_flags_1 && (dynamic->flags_1 & URP_DF_1_NOW) != 0U))) {
        return URP_STATUS_UNSUPPORTED;
    }

    size_t entry_count = (size_t)(dynamic->pltrelsz / 24U);
    if (dynamic->candidate_work != NULL
        && !urp_provider_work_take(dynamic->candidate_work, (uint64_t)entry_count)) {
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
            &rela_offset,
            dynamic->candidate_work)) {
        return URP_STATUS_LOAD_FAILED;
    }

    const uint8_t *rela = image + rela_offset;
    size_t tls_resolver_count = 0U;
    for (size_t index = 0U; index < entry_count; ++index) {
        const uint8_t *entry = rela + index * 24U;
        uint64_t target = urp_read_u64_le(entry);
        uint64_t info = urp_read_u64_le(entry + 8U);
        uint32_t type = (uint32_t)info;
        uint64_t symbol = info >> 32U;
        uint64_t symbol_delta;
        uint64_t symbol_address;
        size_t symbol_offset;
        if ((type != URP_R_AARCH64_JUMP_SLOT && type != URP_R_AARCH64_TLSDESC)
            || symbol == 0U
            || !urp_checked_mul_u64(symbol, dynamic->syment, &symbol_delta)
            || !urp_checked_add_u64(dynamic->symtab, symbol_delta, &symbol_address)
            || !urp_find_load_range(
                image, image_size, program_header_offset, program_header_count,
                symbol_address, dynamic->syment, 0U, 1, &symbol_offset,
                dynamic->candidate_work)) {
            return URP_STATUS_UNSUPPORTED;
        }

        const uint8_t *symbol_record = image + symbol_offset;
        uint32_t name_offset = urp_read_u32_le(symbol_record);
        uint8_t info_byte = symbol_record[4U];
        uint8_t other = symbol_record[5U];
        uint16_t section_index = urp_read_u16_le(symbol_record + 6U);
        uint8_t symbol_binding = (uint8_t)(info_byte >> 4U);
        uint8_t symbol_type = (uint8_t)(info_byte & 0x0fU);
        if (other != URP_STV_DEFAULT
            || !dynamic->has_strtab || !dynamic->has_strsz
            || dynamic->strsz == 0U || name_offset >= dynamic->strsz
            || dynamic->strsz > (uint64_t)SIZE_MAX) {
            return URP_STATUS_UNSUPPORTED;
        }
        if (type == URP_R_AARCH64_JUMP_SLOT) {
            if (!dynamic->has_relaent
                || (symbol_binding != URP_STB_WEAK && symbol_binding != URP_STB_GLOBAL)
                || symbol_type != URP_STT_FUNC
                || section_index != URP_SHN_UNDEF) {
                return URP_STATUS_UNSUPPORTED;
            }
        } else if (symbol_type != URP_STT_TLS
            || section_index == URP_SHN_UNDEF
            || (symbol_binding != 0U && symbol_binding != URP_STB_GLOBAL && symbol_binding != URP_STB_WEAK)
            || !urp_validate_defined_tls_symbol(
                image,
                image_size,
                dynamic,
                program_header_offset,
                program_header_count,
                entry,
                symbol)
            || target % sizeof(uint64_t) != 0U
            || !urp_find_load_range(
                image,
                image_size,
                program_header_offset,
                program_header_count,
                target,
                16U,
                URP_PF_W,
                0,
                NULL,
                dynamic->candidate_work)) {
            return URP_STATUS_UNSUPPORTED;
        }

        size_t strings_offset;
        if (!urp_find_load_range(
                image, image_size, program_header_offset, program_header_count,
                dynamic->strtab, dynamic->strsz, 0U, 1, &strings_offset,
                dynamic->candidate_work)
            || name_offset > SIZE_MAX - strings_offset) {
            return URP_STATUS_LOAD_FAILED;
        }
        size_t name_file_offset = strings_offset + (size_t)name_offset;
        size_t remaining = (size_t)dynamic->strsz - (size_t)name_offset;
        const void *terminator = NULL;
        if (remaining != 0U && dynamic->candidate_work != NULL) {
            size_t scan = 0U;
            while (scan < remaining) {
                if (!urp_provider_work_take(dynamic->candidate_work, 1U)) {
                    return URP_STATUS_UNSUPPORTED;
                }
                if (image[name_file_offset + scan] == 0U) {
                    terminator = image + name_file_offset + scan;
                    break;
                }
                ++scan;
            }
        } else if (remaining != 0U) {
            terminator = memchr(image + name_file_offset, 0, remaining);
        }
        if (remaining == 0U || image[name_file_offset] == 0U || terminator == NULL
            || (type == URP_R_AARCH64_JUMP_SLOT
                && !urp_validate_relocation_target(
                    image, image_size, program_header_offset, program_header_count,
                    target, dynamic->candidate_work))) {
            return URP_STATUS_UNSUPPORTED;
        }

        uintptr_t name_address = (uintptr_t)(image + name_file_offset);
        uintptr_t terminator_address = (uintptr_t)terminator;
        if (terminator_address < name_address) {
            return URP_STATUS_LOAD_FAILED;
        }
        size_t name_length = (size_t)(terminator_address - name_address);
        if (dynamic->candidate_work != NULL
            && !urp_provider_work_take(dynamic->candidate_work, (uint64_t)name_length)) {
            return URP_STATUS_UNSUPPORTED;
        }
        int is_tls_resolver = name_length == sizeof("__tls_get_addr") - 1U
            && memcmp(image + name_file_offset, "__tls_get_addr", name_length) == 0;
        if (type == URP_R_AARCH64_JUMP_SLOT && is_tls_resolver) {
            if (++tls_resolver_count > 1U
                || dynamic->needed_count != 2U
                || !dynamic->has_version_tags
                || dynamic->has_symbolic
                || symbol_binding != URP_STB_GLOBAL) {
                return URP_STATUS_UNSUPPORTED;
            }
        } else if (type == URP_R_AARCH64_JUMP_SLOT
            && symbol_binding != URP_STB_WEAK) {
            return URP_STATUS_UNSUPPORTED;
        } else if (dynamic->needed_count != 0U
            || dynamic->has_version_tags
            || dynamic->has_symbolic) {
            return URP_STATUS_UNSUPPORTED;
        }
    }

    if (tls_resolver_count != 0U
        && dynamic->needed_count != 1U
        && dynamic->needed_count != 2U) {
        return URP_STATUS_UNSUPPORTED;
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
            &strings_offset,
            dynamic->candidate_work)
        || string_offset > SIZE_MAX - strings_offset) {
        return 0;
    }

    size_t relative_offset = (size_t)string_offset;
    size_t remaining = (size_t)dynamic->strsz - relative_offset;
    size_t file_offset = strings_offset + relative_offset;
    size_t length = 0U;
    if (dynamic->candidate_work != NULL) {
        while (length < remaining) {
            if (!urp_provider_work_take(dynamic->candidate_work, 1U)) return 0;
            if (image[file_offset + length] == 0U) break;
            ++length;
        }
        if (length == remaining) return 0;
    } else {
        length = strnlen((const char *)(image + file_offset), remaining);
        if (length == remaining) return 0;
    }
    if (string_out != NULL) {
        *string_out = (const char *)(image + file_offset);
    }
    if (string_length_out != NULL) {
        *string_length_out = length;
    }
    return 1;
}

static size_t urp_max_supported_needed_name_length(const char *expected_provider_soname)
{
    static const char *const supported_names[] = {
        "libc.so.6",
        "ld-linux-aarch64.so.1",
        "libc.so",
        "libc.musl-aarch64.so.1",
        "libc.so.1",
        URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME,
    };
    size_t maximum = expected_provider_soname != NULL
        ? strlen(expected_provider_soname) : 0U;
    for (size_t index = 0U;
        index < sizeof(supported_names) / sizeof(supported_names[0]);
        ++index) {
        size_t length = strlen(supported_names[index]);
        if (length > maximum) maximum = length;
    }
    return maximum;
}

static int urp_dynamic_needed_string(
    const uint8_t *image,
    size_t string_table_offset,
    size_t string_table_size,
    uint64_t string_offset,
    size_t maximum_length,
    urp_provider_work *work,
    const char **name_out,
    size_t *length_out)
{
    if (string_offset >= (uint64_t)string_table_size
        || string_offset > (uint64_t)SIZE_MAX) return 0;
    size_t relative_offset = (size_t)string_offset;
    size_t remaining = string_table_size - relative_offset;
    size_t file_offset = string_table_offset + relative_offset;
    const char *name = (const char *)(image + file_offset);
    size_t length;
    if (work == NULL) {
        length = strnlen(name, remaining);
        if (length == remaining) return 0;
    } else {
        size_t scan_limit = maximum_length + 1U;
        if (scan_limit > remaining) scan_limit = remaining;
        for (length = 0U; length < scan_limit; ++length) {
            if (!urp_provider_work_take(work, 1U)) return 0;
#if defined(URP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS)
            if (work->diagnostic_scope == URP_PROVIDER_WORK_DIAGNOSTICS_CANDIDATE) {
                ++urp_provider_test_candidate_needed_string_bytes;
            }
#endif
            if (image[file_offset + length] == 0U) break;
        }
        if (length == scan_limit || length > maximum_length) return 0;
    }
    if (name_out != NULL) *name_out = name;
    if (length_out != NULL) *length_out = length;
    return 1;
}

static int urp_needed_name_equals(const char *name, size_t length, const char *expected)
{
    size_t expected_length = strlen(expected);
    return length == expected_length && memcmp(name, expected, expected_length) == 0;
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
    uint64_t *symbol_count_out,
    urp_provider_work *work)
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
            &hash_offset,
            work)) {
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
            NULL,
            work)
        || prefix_size > (uint64_t)SIZE_MAX
        || bucket_offset > (uint64_t)SIZE_MAX
        || hash_offset > SIZE_MAX - (size_t)bucket_offset) {
        return 0;
    }

    size_t buckets_file_offset = hash_offset + (size_t)bucket_offset;
    uint64_t maximum_symbol_index = first_hashed_symbol - 1U;
    uint64_t total_chain_steps = 0U;
    int found_hashed_symbol = 0;
    if (work != NULL && !urp_provider_work_take(work, bucket_count)) return 0;
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
            if (work != NULL && !urp_provider_work_take(work, 1U)) return 0;
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
                    &chain_file_offset,
                    work)) {
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
        symbol_count_out,
        dynamic->candidate_work);
}

static int urp_provider_gnu_hash_symbol_count(
    const uint8_t *image,
    size_t image_size,
    uint64_t hash_address,
    const urp_provider_load_index *load_index,
    urp_provider_work *work,
    uint64_t *symbol_count_out)
{
    size_t hash_offset;
    uint64_t available;
    if (!urp_provider_find_load_range(
            image, image_size, load_index, work, hash_address, 16U, 0U, 0U,
            &hash_offset, &available)) return 0;

    uint64_t bucket_count = urp_read_u32_le(image + hash_offset);
    uint64_t first_hashed_symbol = urp_read_u32_le(image + hash_offset + 4U);
    uint64_t bloom_word_count = urp_read_u32_le(image + hash_offset + 8U);
    uint64_t bloom_size;
    uint64_t bucket_size;
    uint64_t bucket_offset;
    uint64_t prefix_size;
    if (bucket_count == 0U || first_hashed_symbol == 0U || bloom_word_count == 0U
        || bucket_count > URP_MAX_DYNAMIC_ENTRIES
        || first_hashed_symbol > URP_MAX_DYNAMIC_ENTRIES
        || bloom_word_count > URP_MAX_DYNAMIC_ENTRIES
        || !urp_checked_mul_u64(bloom_word_count, sizeof(uint64_t), &bloom_size)
        || !urp_checked_mul_u64(bucket_count, sizeof(uint32_t), &bucket_size)
        || !urp_checked_add_u64(16U, bloom_size, &bucket_offset)
        || !urp_checked_add_u64(bucket_offset, bucket_size, &prefix_size)
        || prefix_size > available || prefix_size > (uint64_t)SIZE_MAX
        || bucket_offset > (uint64_t)SIZE_MAX
        || !urp_provider_work_take(work, bucket_count)
        || bucket_offset > SIZE_MAX - hash_offset) return 0;
    size_t verified_hash_offset;
    if (!urp_provider_find_load_range(
            image, image_size, load_index, work, hash_address, prefix_size,
            0U, 0U, &verified_hash_offset, NULL)
        || verified_hash_offset != hash_offset) return 0;

    size_t buckets_file_offset = hash_offset + (size_t)bucket_offset;
    uint64_t chain_available = available - prefix_size;
    uint64_t maximum_symbol_index = first_hashed_symbol - 1U;
    uint64_t total_chain_steps = 0U;
    int found_hashed_symbol = 0;
    for (uint64_t bucket_index = 0U; bucket_index < bucket_count; ++bucket_index) {
        uint64_t bucket_delta;
        if (!urp_checked_mul_u64(bucket_index, sizeof(uint32_t), &bucket_delta)
            || bucket_delta > SIZE_MAX - buckets_file_offset) return 0;
        uint64_t symbol_index = urp_read_u32_le(
            image + buckets_file_offset + (size_t)bucket_delta);
        if (symbol_index == 0U) continue;
        if (symbol_index < first_hashed_symbol
            || symbol_index > URP_MAX_DYNAMIC_ENTRIES) return 0;
        found_hashed_symbol = 1;

        int terminated = 0;
        for (uint64_t step = 0U; step < URP_MAX_DYNAMIC_ENTRIES; ++step) {
            if (!urp_provider_work_take(work, 1U)
                || symbol_index < first_hashed_symbol
                || symbol_index > URP_MAX_DYNAMIC_ENTRIES) return 0;
            uint64_t chain_delta;
            if (!urp_checked_mul_u64(
                    symbol_index - first_hashed_symbol, sizeof(uint32_t), &chain_delta)
                || chain_delta > chain_available
                || sizeof(uint32_t) > chain_available - chain_delta
                || chain_delta > SIZE_MAX - (hash_offset + (size_t)prefix_size)) return 0;
            size_t chain_file_offset = hash_offset + (size_t)prefix_size + (size_t)chain_delta;
            uint32_t chain = urp_read_u32_le(image + chain_file_offset);
            if (symbol_index > maximum_symbol_index) maximum_symbol_index = symbol_index;
            ++total_chain_steps;
            if (total_chain_steps > URP_MAX_DYNAMIC_ENTRIES) return 0;
            if ((chain & 1U) != 0U) {
                terminated = 1;
                break;
            }
            if (symbol_index == UINT64_MAX) return 0;
            ++symbol_index;
        }
        if (!terminated) return 0;
    }

    uint64_t chain_entry_count = found_hashed_symbol
        ? maximum_symbol_index - first_hashed_symbol + 1U : 0U;
    uint64_t chain_bytes;
    uint64_t hash_table_size;
    size_t complete_hash_offset;
    if (!urp_checked_mul_u64(chain_entry_count, sizeof(uint32_t), &chain_bytes)
        || !urp_checked_add_u64(prefix_size, chain_bytes, &hash_table_size)
        || !urp_provider_find_load_range(
            image, image_size, load_index, work, hash_address, hash_table_size,
            0U, 0U, &complete_hash_offset, NULL)
        || complete_hash_offset != hash_offset) return 0;
    if (!found_hashed_symbol) {
        *symbol_count_out = first_hashed_symbol;
        return 1;
    }
    if (!urp_checked_add_u64(maximum_symbol_index, 1U, symbol_count_out)
        || *symbol_count_out > URP_MAX_DYNAMIC_ENTRIES) return 0;
    return 1;
}

/*
 * HostContext supports import-side GNU version requirements only for its
 * existing libc singleton and exact libc.so.6 + ld-linux-aarch64.so.1 pair.
 * Each Verneed vn_file must name one of those declared dependencies; the
 * dynamic-segment preflight separately enforces the exact closed pair.
 * Versioned definitions and versioned entry selection remain outside v1.
 */
static urp_status urp_validate_symbol_version_needs(
    const uint8_t *image,
    size_t image_size,
    const urp_dynamic_values *dynamic,
    uint64_t program_header_offset,
    uint16_t program_header_count)
{
#if defined(URP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS)
    ++urp_provider_test_symbol_version_validation_count;
#endif
    if (dynamic->has_verdef || dynamic->has_verdefnum) {
        return URP_STATUS_UNSUPPORTED;
    }
    if (dynamic->duplicate_version_tags) {
        return URP_STATUS_LOAD_FAILED;
    }
    int any_version_tags = dynamic->has_versym
        || dynamic->has_verneed || dynamic->has_verneednum;
    if (!any_version_tags) {
        return URP_STATUS_OK;
    }
    if (dynamic->needed_count != 1U && dynamic->needed_count != 2U) {
        URP_TRACE_VALIDATION_FAILURE("incomplete symbol-version tuple", URP_STATUS_UNSUPPORTED);
        return URP_STATUS_UNSUPPORTED;
    }

    static const char glibc_soname[] = "libc.so.6";
    static const char glibc_loader_soname[] = "ld-linux-aarch64.so.1";
    for (size_t index = 0U; index < dynamic->needed_count; ++index) {
        const char *needed_name;
        size_t needed_name_length;
        if (!urp_dynamic_string(
                image,
                image_size,
                dynamic,
                program_header_offset,
                program_header_count,
                dynamic->needed_offsets[index],
                &needed_name,
                &needed_name_length)) {
            return URP_STATUS_LOAD_FAILED;
        }
        int matches_libc = needed_name_length == sizeof(glibc_soname) - 1U
            && memcmp(needed_name, glibc_soname, sizeof(glibc_soname) - 1U) == 0;
        int matches_loader = dynamic->needed_count == 2U
            && needed_name_length == sizeof(glibc_loader_soname) - 1U
            && memcmp(needed_name, glibc_loader_soname, sizeof(glibc_loader_soname) - 1U) == 0;
        if (!matches_libc && !matches_loader) {
            URP_TRACE_VALIDATION_FAILURE("versioned dependency SONAME", URP_STATUS_UNSUPPORTED);
            return URP_STATUS_UNSUPPORTED;
        }
    }
    if (!dynamic->has_versym
        || !dynamic->has_verneed || !dynamic->has_verneednum
        || dynamic->verneednum == 0U) {
        URP_TRACE_VALIDATION_FAILURE("incomplete symbol-version tuple", URP_STATUS_UNSUPPORTED);
        return URP_STATUS_UNSUPPORTED;
    }

    if (dynamic->has_symbolic) {
        URP_TRACE_VALIDATION_FAILURE("DT_SYMBOLIC with version requirements", URP_STATUS_UNSUPPORTED);
        return URP_STATUS_UNSUPPORTED;
    }
    if (dynamic->has_sysv_hash) {
        URP_TRACE_VALIDATION_FAILURE("DT_HASH with version requirements", URP_STATUS_UNSUPPORTED);
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
            NULL,
            dynamic->candidate_work)) {
        return URP_STATUS_LOAD_FAILED;
    }

    uint64_t version_need_address = dynamic->verneed;
    size_t total_auxiliary_count = 0U;
    size_t record_count = (size_t)dynamic->verneednum;
    if (dynamic->candidate_work != NULL
        && !urp_provider_work_take(dynamic->candidate_work, (uint64_t)record_count)) {
        return URP_STATUS_UNSUPPORTED;
    }
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
                &record_offset,
                dynamic->candidate_work)) {
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
        int matches_libc = file_name_length == sizeof(glibc_soname) - 1U
            && memcmp(file_name, glibc_soname, sizeof(glibc_soname) - 1U) == 0;
        int matches_loader = dynamic->needed_count == 2U
            && file_name_length == sizeof(glibc_loader_soname) - 1U
            && memcmp(file_name, glibc_loader_soname, sizeof(glibc_loader_soname) - 1U) == 0;
        if (!matches_libc && !matches_loader) {
            URP_TRACE_VALIDATION_FAILURE("DT_VERNEED vn_file mismatch", URP_STATUS_UNSUPPORTED);
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
            if (dynamic->candidate_work != NULL
                && !urp_provider_work_take(dynamic->candidate_work, 1U)) {
                return URP_STATUS_UNSUPPORTED;
            }
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
                    &auxiliary_file_offset,
                    dynamic->candidate_work)) {
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
                URP_TRACE_VALIDATION_FAILURE("unsupported DT_VERNEED auxiliary flags", URP_STATUS_UNSUPPORTED);
                return URP_STATUS_UNSUPPORTED;
            }
            if (dynamic->candidate_work != NULL
                && !urp_provider_work_take(
                    dynamic->candidate_work, (uint64_t)version_name_length)) {
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
#if defined(__BIONIC__) || defined(__ANDROID__)
    /* Bionic/Termux currently ignores DT_RELR metadata; reject before dlopen
     * rather than allowing an unrelocated pointer to reach the entry point. */
    return URP_STATUS_UNSUPPORTED;
#endif
    if (!dynamic->has_relrsz || !dynamic->has_relrent
        || dynamic->relrent != sizeof(uint64_t)
        || dynamic->relrsz % dynamic->relrent != 0U) {
        return URP_STATUS_LOAD_FAILED;
    }

    size_t entry_count = (size_t)(dynamic->relrsz / sizeof(uint64_t));
    if (dynamic->candidate_work != NULL
        && !urp_provider_work_take(dynamic->candidate_work, (uint64_t)entry_count)) {
        return URP_STATUS_UNSUPPORTED;
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
            &relr_offset,
            dynamic->candidate_work)) {
        return URP_STATUS_LOAD_FAILED;
    }

    const uint8_t *relr = image + relr_offset;
    uint64_t next = 0U;
    for (size_t index = 0; index < entry_count; ++index) {
        uint64_t entry = urp_read_u64_le(relr + index * sizeof(uint64_t));
        if ((entry & 1U) == 0U) {
            if (!urp_validate_relocation_target(
                    image,
                    image_size,
                    program_header_offset,
                    program_header_count,
                    entry,
                    dynamic->candidate_work)
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
            if (dynamic->candidate_work != NULL
                && !urp_provider_work_take(dynamic->candidate_work, 1U)) {
                return URP_STATUS_UNSUPPORTED;
            }
            uint64_t delta = (uint64_t)(bit - 1U) * sizeof(uint64_t);
            uint64_t target;
            if (!urp_checked_add_u64(next, delta, &target)
                || !urp_validate_relocation_target(
                    image,
                    image_size,
                    program_header_offset,
                    program_header_count,
                    target,
                    dynamic->candidate_work)) {
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
    uint16_t program_header_count,
    const char *expected_provider_soname,
    urp_provider_work *candidate_work,
    size_t *out_dependency_count,
    int *out_uses_provider,
    uint64_t *out_provider_got_virtual_address)
{
    size_t dynamic_offset;
    size_t dynamic_size;
    if (out_dependency_count == NULL) {
        return URP_STATUS_INVALID_ARGUMENT;
    }
    *out_dependency_count = 0U;
    if (out_uses_provider != NULL) *out_uses_provider = 0;
    if (out_provider_got_virtual_address != NULL) *out_provider_got_virtual_address = 0U;
    if (size == 0U
        || size % URP_ELF_DYNAMIC_ENTRY_SIZE != 0U
        || size / URP_ELF_DYNAMIC_ENTRY_SIZE > URP_MAX_DYNAMIC_ENTRIES
        || !urp_range_in_file(image_size, offset, size, &dynamic_offset, &dynamic_size)) {
        return URP_STATUS_LOAD_FAILED;
    }

    const uint8_t *dynamic = image + dynamic_offset;
    size_t entry_count = dynamic_size / URP_ELF_DYNAMIC_ENTRY_SIZE;
    if (candidate_work != NULL
        && !urp_provider_work_take_dynamic_entries(candidate_work, (uint64_t)entry_count)) {
        return URP_STATUS_UNSUPPORTED;
    }
    urp_dynamic_values values = {0};
    values.candidate_work = candidate_work;
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
            /* Closed P3 graph: a libc singleton or exact two-name glibc pair. */
            if (needed_count >= sizeof(values.needed_offsets) / sizeof(values.needed_offsets[0])) {
                return URP_STATUS_UNSUPPORTED;
            }
            values.needed_offsets[needed_count++] = urp_read_u64_le(entry + 8U);
            values.needed_count = needed_count;
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
        case URP_DT_AUDIT:
        case URP_DT_DEPAUDIT:
        case URP_DT_CONFIG:
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
            values.has_version_tags = 1;
            if (values.has_versym) {
                values.duplicate_version_tags = 1;
                break;
            }
            values.versym = urp_read_u64_le(entry + 8U);
            values.has_versym = 1;
            break;
        /* Versioned definitions are collected so provider policy rejects them before generic traversal. */
        case URP_DT_VERDEF:
            values.has_version_tags = 1;
            values.has_verdef = 1;
            break;
        case URP_DT_VERDEFNUM:
            values.has_version_tags = 1;
            values.has_verdefnum = 1;
            break;
        case URP_DT_VERNEED:
            values.has_version_tags = 1;
            if (values.has_verneed) {
                values.duplicate_version_tags = 1;
                break;
            }
            values.verneed = urp_read_u64_le(entry + 8U);
            values.has_verneed = 1;
            break;
        case URP_DT_VERNEEDNUM:
            values.has_version_tags = 1;
            if (values.has_verneednum) {
                values.duplicate_version_tags = 1;
                break;
            }
            values.verneednum = urp_read_u64_le(entry + 8U);
            values.has_verneednum = 1;
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

    if (values.needed_count != 0U) {
        if (!values.has_strtab || !values.has_strsz
            || values.strsz == 0U || values.strsz > (uint64_t)SIZE_MAX) {
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
                &string_offset,
                candidate_work)
            || !urp_u64_to_size(values.strsz, &string_size)) {
            return URP_STATUS_LOAD_FAILED;
        }
        size_t libc_count = 0U;
        size_t loader_count = 0U;
        size_t provider_count = 0U;
        size_t maximum_needed_length = urp_max_supported_needed_name_length(
            expected_provider_soname);
        for (size_t index = 0U; index < values.needed_count; ++index) {
            if (values.needed_offsets[index] >= values.strsz) {
                return URP_STATUS_LOAD_FAILED;
            }
            uint64_t needed_string_offset;
            if (!urp_checked_add_u64(
                    (uint64_t)string_offset,
                    values.needed_offsets[index],
                    &needed_string_offset)
                || needed_string_offset > (uint64_t)image_size
                || needed_string_offset > (uint64_t)SIZE_MAX) {
                return URP_STATUS_LOAD_FAILED;
            }
            const char *needed;
            size_t needed_length;
            if (!urp_dynamic_needed_string(
                    image, string_offset, string_size, values.needed_offsets[index],
                    maximum_needed_length, candidate_work, &needed, &needed_length)) {
                return candidate_work != NULL
                    ? URP_STATUS_UNSUPPORTED : URP_STATUS_LOAD_FAILED;
            }
            if (expected_provider_soname != NULL
                && urp_needed_name_equals(needed, needed_length, expected_provider_soname)) {
                ++provider_count;
            } else if (urp_needed_name_equals(needed, needed_length, "libc.so.6")) {
                ++libc_count;
            } else if (urp_needed_name_equals(needed, needed_length, "ld-linux-aarch64.so.1")) {
                ++loader_count;
            } else if (values.needed_count == 1U
                && (urp_needed_name_equals(needed, needed_length, "libc.so")
                    || urp_needed_name_equals(needed, needed_length, "libc.musl-aarch64.so.1")
                    || urp_needed_name_equals(needed, needed_length, "libc.so.1"))) {
                ++libc_count;
            } else {
                return URP_STATUS_UNSUPPORTED;
            }
        }
        if (provider_count != 0U) {
            if (provider_count != 1U || values.needed_count != 1U) {
                return URP_STATUS_UNSUPPORTED;
            }
            values.provider_dependency = 1;
        } else if ((values.needed_count == 1U && libc_count != 1U)
            || (values.needed_count == 2U && (libc_count != 1U || loader_count != 1U))) {
            return URP_STATUS_UNSUPPORTED;
        }
    }

    if (values.provider_dependency && values.has_version_tags) {
        URP_TRACE_VALIDATION_FAILURE("provider dependency with symbol-version tags", URP_STATUS_UNSUPPORTED);
        return URP_STATUS_UNSUPPORTED;
    }

    urp_status status = urp_validate_symbol_version_needs(
        image,
        image_size,
        &values,
        program_header_offset,
        program_header_count);
    if (status != URP_STATUS_OK) {
        URP_TRACE_VALIDATION_FAILURE("symbol-version needs", status);
        return status;
    }
    status = urp_validate_rela(
        image,
        image_size,
        &values,
        program_header_offset,
        program_header_count);
    if (status != URP_STATUS_OK) {
        URP_TRACE_VALIDATION_FAILURE("RELA", status);
        return status;
    }
    status = urp_validate_plt_rela(
        image,
        image_size,
        &values,
        program_header_offset,
        program_header_count);
    if (status != URP_STATUS_OK) {
        URP_TRACE_VALIDATION_FAILURE("PLT RELA", status);
        return status;
    }
    status = urp_validate_relr(
        image,
        image_size,
        &values,
        program_header_offset,
        program_header_count);
    if (status != URP_STATUS_OK) {
        URP_TRACE_VALIDATION_FAILURE("RELR", status);
    } else {
        if (values.provider_dependency
            && (!values.has_rela || !values.has_relasz || !values.has_relaent
                || values.relaent != 24U || values.relasz != 24U
                || values.provider_got_address == 0U)) {
            return URP_STATUS_UNSUPPORTED;
        }
        *out_dependency_count = values.needed_count;
        if (out_uses_provider != NULL) *out_uses_provider = values.provider_dependency;
        if (out_provider_got_virtual_address != NULL) {
            *out_provider_got_virtual_address = values.provider_got_address;
        }
    }
    return status;
}

urp_status urp_host_image_validate_with_provider(
    const void *bytes,
    size_t image_size,
    const char *expected_provider_soname,
    size_t *out_dependency_count,
    int *out_uses_provider,
    uint64_t *out_provider_got_virtual_address)
{
#if defined(URP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS)
    urp_provider_test_candidate_work_used = 0U;
    urp_provider_test_candidate_dynamic_entries = 0U;
    urp_provider_test_candidate_range_work = 0U;
    urp_provider_test_candidate_needed_string_bytes = 0U;
    urp_provider_test_consumer_rela_validation_count = 0U;
    urp_provider_test_symbol_version_validation_count = 0U;
#endif
    if (out_dependency_count == NULL || out_uses_provider == NULL
        || out_provider_got_virtual_address == NULL) {
        return URP_STATUS_INVALID_ARGUMENT;
    }
    *out_dependency_count = 0U;
    *out_uses_provider = 0;
    *out_provider_got_virtual_address = 0U;
    if (expected_provider_soname != NULL
        && strcmp(expected_provider_soname, URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME) != 0) {
        return URP_STATUS_UNSUPPORTED;
    }
    urp_provider_work candidate_work = {
        .limit = urp_provider_work_limit(),
        .used = 0U,
#if defined(URP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS)
        .diagnostic_scope = expected_provider_soname != NULL
            ? URP_PROVIDER_WORK_DIAGNOSTICS_CANDIDATE
            : URP_PROVIDER_WORK_DIAGNOSTICS_NONE,
#endif
    };
    urp_provider_work *candidate_work_ptr = expected_provider_soname != NULL
        ? &candidate_work : NULL;
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

    if (candidate_work_ptr != NULL
        && !urp_provider_work_take(candidate_work_ptr, program_header_count)) {
        return URP_STATUS_UNSUPPORTED;
    }

    size_t load_count = 0U;
    size_t dependency_count = 0U;
    size_t dynamic_segment_count = 0U;
    size_t tls_segment_count = 0U;
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
            if (++dynamic_segment_count != 1U) {
                return URP_STATUS_LOAD_FAILED;
            }
            urp_status status = urp_validate_dynamic_segment(
                image,
                image_size,
                file_offset,
                file_size,
                program_header_offset,
                program_header_count,
                expected_provider_soname,
                candidate_work_ptr,
                &dependency_count,
                out_uses_provider,
                out_provider_got_virtual_address);
            if (status != URP_STATUS_OK) {
                URP_TRACE_VALIDATION_FAILURE("PT_DYNAMIC", status);
                return status;
            }
            break;
        }
        case URP_PT_TLS:
            /*
             * HostContext and managed HostContext materialization share the
             * sectioned, writable-owner PT_TLS contract. StructuralElf may
             * retain broader observation-only facts, but handoff accepts only
             * one non-empty readable TLS segment with an exact writable load
             * owner and a congruent file/template range.
             */
            ++tls_segment_count;
            if (tls_segment_count > 1U
                || memory_size == 0U
                || (flags & URP_PF_X) != 0U
                || (flags & URP_PF_R) == 0U
                || (flags & ~(URP_PF_R | URP_PF_W)) != 0U
                || !urp_find_tls_owner(
                    image,
                    image_size,
                    program_header_offset,
                    program_header_count,
                    file_offset,
                    virtual_address,
                    file_size,
                    memory_size,
                    flags,
                    candidate_work_ptr)) {
                URP_TRACE_VALIDATION_FAILURE("PT_TLS", URP_STATUS_UNSUPPORTED);
                return URP_STATUS_UNSUPPORTED;
            }
            break;
        case URP_PT_INTERP:
            return URP_STATUS_UNSUPPORTED;
        case URP_PT_GNU_PROPERTY:
            if ((flags & (URP_PF_W | URP_PF_X)) != 0U
                || urp_validate_gnu_property(image, image_size, file_offset, file_size)
                    != URP_STATUS_OK) {
                URP_TRACE_VALIDATION_FAILURE("PT_GNU_PROPERTY", URP_STATUS_UNSUPPORTED);
                return URP_STATUS_UNSUPPORTED;
            }
            break;
        case URP_PT_GNU_STACK:
            if ((flags & URP_PF_X) != 0U) {
                URP_TRACE_VALIDATION_FAILURE("executable PT_GNU_STACK", URP_STATUS_UNSUPPORTED);
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
    *out_dependency_count = dependency_count;
    return URP_STATUS_OK;
}

static int urp_provider_expected_build_id(
    const char *expected_hex,
    uint8_t expected_bytes[20])
{
    if (expected_hex == NULL || strlen(expected_hex) != 40U) return 0;
    for (size_t index = 0U; index < 20U; ++index) {
        unsigned int high;
        unsigned int low;
        char high_char = expected_hex[index * 2U];
        char low_char = expected_hex[(index * 2U) + 1U];
        if (high_char >= '0' && high_char <= '9') high = (unsigned int)(high_char - '0');
        else if (high_char >= 'a' && high_char <= 'f') high = (unsigned int)(high_char - 'a') + 10U;
        else if (high_char >= 'A' && high_char <= 'F') high = (unsigned int)(high_char - 'A') + 10U;
        else return 0;
        if (low_char >= '0' && low_char <= '9') low = (unsigned int)(low_char - '0');
        else if (low_char >= 'a' && low_char <= 'f') low = (unsigned int)(low_char - 'a') + 10U;
        else if (low_char >= 'A' && low_char <= 'F') low = (unsigned int)(low_char - 'A') + 10U;
        else return 0;
        expected_bytes[index] = (uint8_t)((high << 4U) | low);
    }
    return 1;
}

typedef struct urp_provider_symbol {
    uint64_t value;
    uint64_t size;
    uint16_t section_index;
    uint8_t binding;
    uint8_t type;
    uint8_t visibility;
    size_t count;
} urp_provider_symbol;

static urp_status urp_host_external_provider_validate_impl(
    const void *bytes,
    size_t image_size,
    const char *expected_soname,
    const char *expected_build_id_hex,
    urp_host_external_provider_facts *out_facts,
    urp_provider_work *work)
{
    if (out_facts == NULL || work == NULL || expected_soname == NULL
        || strcmp(expected_soname, URP_HOST_EXTERNAL_TABLE_PROVIDER_SONAME) != 0) {
        return URP_STATUS_INVALID_ARGUMENT;
    }
    memset(out_facts, 0, sizeof(*out_facts));
    const uint8_t *image = (const uint8_t *)bytes;
    if (image == NULL || image_size == 0U) return URP_STATUS_LOAD_FAILED;
    uint8_t expected_build_id[20];
    if (!urp_provider_expected_build_id(expected_build_id_hex, expected_build_id)) {
        return URP_STATUS_UNSUPPORTED;
    }

    static const uint8_t elf_magic[] = {0x7fU, 'E', 'L', 'F'};
    if (image_size < URP_ELF_HEADER_SIZE
        || memcmp(image, elf_magic, sizeof(elf_magic)) != 0
        || image[4] != URP_ELF_CLASS_64 || image[5] != URP_ELF_DATA_LSB
        || image[6] != URP_ELF_VERSION_CURRENT
        || urp_read_u16_le(image + 16U) != URP_ELF_TYPE_DYN
        || urp_read_u16_le(image + 18U) != URP_ELF_MACHINE_AARCH64
        || urp_read_u32_le(image + 20U) != URP_ELF_VERSION_CURRENT
        || urp_read_u16_le(image + 52U) != URP_ELF_HEADER_SIZE
        || urp_read_u16_le(image + 54U) != URP_ELF_PROGRAM_HEADER_SIZE) {
        return URP_STATUS_UNSUPPORTED;
    }
    uint64_t program_header_offset = urp_read_u64_le(image + 32U);
    uint16_t program_header_count = urp_read_u16_le(image + 56U);
    uint64_t program_headers_size;
    if (program_header_count == 0U || program_header_count > URP_MAX_PROGRAM_HEADERS
        || !urp_checked_mul_u64(program_header_count, URP_ELF_PROGRAM_HEADER_SIZE,
            &program_headers_size)
        || !urp_range_in_file(image_size, program_header_offset, program_headers_size, NULL, NULL)
        || !urp_provider_work_take(work, program_header_count)) {
        return URP_STATUS_UNSUPPORTED;
    }

    size_t preflight_dynamic_count = 0U;
    uint64_t preflight_dynamic_offset = 0U;
    uint64_t preflight_dynamic_size = 0U;
    for (uint16_t index = 0U; index < program_header_count; ++index) {
        const uint8_t *header;
        if (!urp_get_program_header(
                image, image_size, program_header_offset, program_header_count, index, &header)) {
            return URP_STATUS_UNSUPPORTED;
        }
        uint32_t program_header_type = urp_read_u32_le(header);
        if (program_header_type == URP_PT_TLS || program_header_type == URP_PT_INTERP) {
            return URP_STATUS_UNSUPPORTED;
        }
        if (program_header_type != URP_PT_DYNAMIC) continue;
        ++preflight_dynamic_count;
        preflight_dynamic_offset = urp_read_u64_le(header + 8U);
        preflight_dynamic_size = urp_read_u64_le(header + 32U);
    }
    if (preflight_dynamic_count != 1U
        || preflight_dynamic_size == 0U
        || preflight_dynamic_size % URP_ELF_DYNAMIC_ENTRY_SIZE != 0U
        || !urp_range_in_file(
            image_size, preflight_dynamic_offset, preflight_dynamic_size, NULL, NULL)) {
        return URP_STATUS_UNSUPPORTED;
    }
    uint64_t preflight_dynamic_entries = preflight_dynamic_size / URP_ELF_DYNAMIC_ENTRY_SIZE;
    if (preflight_dynamic_entries > URP_MAX_DYNAMIC_ENTRIES
        || !urp_provider_work_take(work, preflight_dynamic_entries)) return URP_STATUS_UNSUPPORTED;
    size_t preflight_dynamic_file_offset;
    size_t preflight_dynamic_file_size;
    if (!urp_range_in_file(image_size, preflight_dynamic_offset, preflight_dynamic_size,
            &preflight_dynamic_file_offset, &preflight_dynamic_file_size)) {
        return URP_STATUS_UNSUPPORTED;
    }
    int preflight_terminated = 0;
    for (size_t index = 0U; index < preflight_dynamic_file_size / URP_ELF_DYNAMIC_ENTRY_SIZE; ++index) {
        uint64_t tag = urp_read_u64_le(
            image + preflight_dynamic_file_offset + index * URP_ELF_DYNAMIC_ENTRY_SIZE);
        if (tag == 0U) {
            preflight_terminated = 1;
            break;
        }
        switch (tag) {
        case URP_DT_SONAME:
        case URP_DT_STRTAB:
        case URP_DT_STRSZ:
        case URP_DT_SYMTAB:
        case URP_DT_SYMENT:
        case URP_DT_GNU_HASH:
            break;
        default:
            return URP_STATUS_UNSUPPORTED;
        }
    }
    uint64_t generic_validation_work;
    if (!preflight_terminated
        || !urp_checked_add_u64(program_header_count, preflight_dynamic_entries,
            &generic_validation_work)
        || !urp_provider_work_take(work, generic_validation_work)) {
        return URP_STATUS_UNSUPPORTED;
    }
    size_t dependency_count = 0U;
    if (urp_host_image_validate(image, image_size, &dependency_count) != URP_STATUS_OK
        || dependency_count != 0U) return URP_STATUS_UNSUPPORTED;

    urp_provider_load_index load_index;
    if (!urp_provider_build_load_index(
            image, image_size, program_header_offset, program_header_count,
            work, &load_index)) return URP_STATUS_UNSUPPORTED;
    size_t dynamic_count = 0U;
    size_t note_count = 0U;
    uint64_t dynamic_file_offset = 0U;
    uint64_t dynamic_file_size = 0U;
    int have_build_id = 0;
    uint8_t actual_build_id[20] = {0};
    if (!urp_provider_work_take(work, program_header_count)) return URP_STATUS_UNSUPPORTED;
    for (uint16_t index = 0U; index < program_header_count; ++index) {
        const uint8_t *header;
        if (!urp_get_program_header(
                image, image_size, program_header_offset, program_header_count, index, &header)) {
            return URP_STATUS_LOAD_FAILED;
        }
        uint32_t type = urp_read_u32_le(header);
        uint32_t flags = urp_read_u32_le(header + 4U);
        uint64_t file_offset = urp_read_u64_le(header + 8U);
        uint64_t file_size = urp_read_u64_le(header + 32U);
        if (type == URP_PT_LOAD && (flags & (URP_PF_W | URP_PF_X)) == (URP_PF_W | URP_PF_X)) {
            return URP_STATUS_UNSUPPORTED;
        }
        if (type == URP_PT_DYNAMIC) {
            ++dynamic_count;
            dynamic_file_offset = file_offset;
            dynamic_file_size = file_size;
        }
        if (type != URP_PT_NOTE) continue;
        ++note_count;
        size_t notes_offset;
        size_t notes_size;
        if (!urp_range_in_file(image_size, file_offset, file_size, &notes_offset, &notes_size)) {
            return URP_STATUS_LOAD_FAILED;
        }
        size_t cursor = 0U;
        while (cursor < notes_size) {
            if (!urp_provider_work_take(work, 1U)
                || notes_size - cursor < 12U) return URP_STATUS_LOAD_FAILED;
            const uint8_t *note = image + notes_offset + cursor;
            uint32_t name_size = urp_read_u32_le(note);
            uint32_t descriptor_size = urp_read_u32_le(note + 4U);
            uint32_t note_type = urp_read_u32_le(note + 8U);
            uint64_t padded_name = ((uint64_t)name_size + 3U) & ~UINT64_C(3);
            uint64_t padded_descriptor = ((uint64_t)descriptor_size + 3U) & ~UINT64_C(3);
            uint64_t record_size;
            if (!urp_checked_add_u64(12U, padded_name, &record_size)
                || !urp_checked_add_u64(record_size, padded_descriptor, &record_size)
                || record_size > (uint64_t)(notes_size - cursor)) {
                return URP_STATUS_LOAD_FAILED;
            }
            uint64_t descriptor_offset;
            if (!urp_checked_add_u64(12U, padded_name, &descriptor_offset)
                || descriptor_offset > (uint64_t)SIZE_MAX) {
                return URP_STATUS_LOAD_FAILED;
            }
            if (name_size == 4U && note_type == 3U
                && memcmp(note + 12U, "GNU\0", 4U) == 0) {
                if (have_build_id || descriptor_size != sizeof(actual_build_id)) {
                    return URP_STATUS_UNSUPPORTED;
                }
                memcpy(actual_build_id, note + (size_t)descriptor_offset, sizeof(actual_build_id));
                have_build_id = 1;
            }
            cursor += (size_t)record_size;
        }
    }
    if (dynamic_count != 1U || note_count == 0U || !have_build_id
        || memcmp(actual_build_id, expected_build_id, sizeof(actual_build_id)) != 0
        || dynamic_file_size == 0U || dynamic_file_size % URP_ELF_DYNAMIC_ENTRY_SIZE != 0U) {
        return URP_STATUS_UNSUPPORTED;
    }

    size_t dynamic_offset;
    size_t dynamic_size;
    if (!urp_range_in_file(
            image_size, dynamic_file_offset, dynamic_file_size, &dynamic_offset, &dynamic_size)) {
        return URP_STATUS_LOAD_FAILED;
    }
    uint64_t string_table = 0U;
    uint64_t string_table_size = 0U;
    uint64_t symbol_table = 0U;
    uint64_t symbol_entry_size = 0U;
    uint64_t gnu_hash = 0U;
    uint64_t soname_offset = 0U;
    int has_string_table = 0;
    int has_string_table_size = 0;
    int has_symbol_table = 0;
    int has_symbol_entry_size = 0;
    int has_gnu_hash = 0;
    int has_soname = 0;
    int dynamic_terminated = 0;
    size_t dynamic_entries = dynamic_size / URP_ELF_DYNAMIC_ENTRY_SIZE;
    if (!urp_provider_work_take(work, (uint64_t)dynamic_entries)) return URP_STATUS_UNSUPPORTED;
    for (size_t index = 0U; index < dynamic_entries; ++index) {
        const uint8_t *entry = image + dynamic_offset + index * URP_ELF_DYNAMIC_ENTRY_SIZE;
        uint64_t tag = urp_read_u64_le(entry);
        uint64_t value = urp_read_u64_le(entry + 8U);
        if (tag == 0U) {
            dynamic_terminated = 1;
            break;
        }
        switch (tag) {
        case URP_DT_NEEDED:
        case URP_DT_RPATH:
        case URP_DT_RUNPATH:
        case URP_DT_AUXILIARY:
        case URP_DT_FILTER:
        case URP_DT_AUDIT:
        case URP_DT_DEPAUDIT:
        case URP_DT_CONFIG:
        case URP_DT_RELA:
        case URP_DT_RELASZ:
        case URP_DT_RELAENT:
        case URP_DT_JMPREL:
        case URP_DT_PLTRELSZ:
        case URP_DT_PLTREL:
        case URP_DT_REL:
        case URP_DT_RELSZ:
        case URP_DT_RELENT:
        case URP_DT_RELR:
        case URP_DT_RELRSZ:
        case URP_DT_RELRENT:
        case URP_DT_TEXTREL:
        case URP_DT_VERSYM:
        case URP_DT_VERNEED:
        case URP_DT_VERNEEDNUM:
        case URP_DT_VERDEF:
        case URP_DT_VERDEFNUM:
            return URP_STATUS_UNSUPPORTED;
        case URP_DT_SONAME:
            if (has_soname) return URP_STATUS_UNSUPPORTED;
            soname_offset = value;
            has_soname = 1;
            break;
        case URP_DT_STRTAB:
            if (has_string_table) return URP_STATUS_UNSUPPORTED;
            string_table = value;
            has_string_table = 1;
            break;
        case URP_DT_STRSZ:
            if (has_string_table_size) return URP_STATUS_UNSUPPORTED;
            string_table_size = value;
            has_string_table_size = 1;
            break;
        case URP_DT_SYMTAB:
            if (has_symbol_table) return URP_STATUS_UNSUPPORTED;
            symbol_table = value;
            has_symbol_table = 1;
            break;
        case URP_DT_SYMENT:
            if (has_symbol_entry_size) return URP_STATUS_UNSUPPORTED;
            symbol_entry_size = value;
            has_symbol_entry_size = 1;
            break;
        case URP_DT_GNU_HASH:
            if (has_gnu_hash) return URP_STATUS_UNSUPPORTED;
            gnu_hash = value;
            has_gnu_hash = 1;
            break;
        default:
            return URP_STATUS_UNSUPPORTED;
        }
    }
    if (!dynamic_terminated || !has_soname || !has_string_table || !has_string_table_size
        || !has_symbol_table || !has_symbol_entry_size || !has_gnu_hash
        || symbol_entry_size != 24U || string_table_size == 0U
        || string_table_size > (uint64_t)SIZE_MAX) {
        return URP_STATUS_UNSUPPORTED;
    }

    size_t string_table_offset;
    if (!urp_provider_find_load_range(
            image, image_size, &load_index, work, string_table, string_table_size,
            0U, 0U, &string_table_offset, NULL)) return URP_STATUS_UNSUPPORTED;
    size_t string_table_byte_size = (size_t)string_table_size;
    const uint8_t *strings = image + string_table_offset;
    if (strings[0] != 0U || strings[string_table_byte_size - 1U] != 0U) {
        return URP_STATUS_UNSUPPORTED;
    }
    const char *soname;
    size_t soname_length;
    if (!urp_provider_string(
            image, string_table_offset, string_table_byte_size, soname_offset,
            work, &soname, &soname_length)
        || soname_length != strlen(expected_soname)
        || memcmp(soname, expected_soname, soname_length) != 0) {
        return URP_STATUS_UNSUPPORTED;
    }

    uint64_t symbol_count;
    uint64_t symbol_table_size;
    size_t symbol_table_offset;
    if (!urp_provider_gnu_hash_symbol_count(
            image, image_size, gnu_hash, &load_index, work, &symbol_count)
        || symbol_count == 0U || symbol_count > URP_MAX_DYNAMIC_ENTRIES
        || !urp_checked_mul_u64(symbol_count, symbol_entry_size, &symbol_table_size)
        || !urp_provider_find_load_range(
            image, image_size, &load_index, work, symbol_table,
            symbol_table_size, 0U, 0U, &symbol_table_offset, NULL)) {
        return URP_STATUS_UNSUPPORTED;
    }

    static const char *const required_names[] = {
        URP_HOST_EXTERNAL_TABLE_SYMBOL,
        "urp_provider_target_0",
        "urp_provider_target_1",
        "urp_provider_target_2",
        "urp_provider_target_3"
    };
    uint64_t string_cost_per_symbol = 0U;
    for (size_t required_index = 0U;
         required_index < sizeof(required_names) / sizeof(required_names[0]);
         ++required_index) {
        uint64_t name_cost = (uint64_t)strlen(required_names[required_index]) + 1U;
        if (!urp_checked_add_u64(string_cost_per_symbol, name_cost, &string_cost_per_symbol)) {
            return URP_STATUS_UNSUPPORTED;
        }
    }
    uint64_t total_string_cost;
    if (!urp_checked_mul_u64(symbol_count, string_cost_per_symbol, &total_string_cost)
        || !urp_provider_work_take(work, symbol_count)
        || !urp_provider_work_take(work, total_string_cost)) return URP_STATUS_UNSUPPORTED;

    urp_provider_symbol symbols[sizeof(required_names) / sizeof(required_names[0])] = {{0}};
    for (uint64_t index = 0U; index < symbol_count; ++index) {
        size_t row_offset = symbol_table_offset + (size_t)(index * symbol_entry_size);
        const uint8_t *record = image + row_offset;
        uint64_t name_offset = urp_read_u32_le(record);
        if (name_offset >= string_table_size) return URP_STATUS_UNSUPPORTED;
        size_t name_index = (size_t)name_offset;
        size_t remaining = string_table_byte_size - name_index;
        const uint8_t *name = strings + name_index;
        for (size_t required_index = 0U;
             required_index < sizeof(required_names) / sizeof(required_names[0]);
             ++required_index) {
            size_t required_length = strlen(required_names[required_index]);
            if (required_length >= remaining
                || name[0] != (uint8_t)required_names[required_index][0]
                || memcmp(name, required_names[required_index], required_length) != 0
                || name[required_length] != 0U) continue;
            urp_provider_symbol *symbol = &symbols[required_index];
            ++symbol->count;
            symbol->value = urp_read_u64_le(record + 8U);
            symbol->size = urp_read_u64_le(record + 16U);
            symbol->binding = (uint8_t)(record[4U] >> 4U);
            symbol->type = (uint8_t)(record[4U] & 0x0fU);
            symbol->visibility = (uint8_t)(record[5U] & 0x03U);
            symbol->section_index = urp_read_u16_le(record + 6U);
        }
    }
    for (size_t index = 0U; index < sizeof(symbols) / sizeof(symbols[0]); ++index) {
        uint8_t expected_visibility = index == 0U ? URP_STV_DEFAULT : URP_STV_PROTECTED;
        if (symbols[index].count != 1U || symbols[index].section_index == URP_SHN_UNDEF
            || symbols[index].binding != URP_STB_GLOBAL
            || symbols[index].visibility != expected_visibility) {
            return URP_STATUS_UNSUPPORTED;
        }
    }
    size_t table_file_offset;
    if (symbols[0].type != URP_STT_OBJECT || symbols[0].size != 16U
        || !urp_provider_find_load_range(
            image, image_size, &load_index, work, symbols[0].value,
            symbols[0].size, URP_PF_R, URP_PF_W | URP_PF_X,
            &table_file_offset, NULL)) {
        return URP_STATUS_UNSUPPORTED;
    }
    if (symbols[1].type != URP_STT_FUNC || symbols[2].type != URP_STT_FUNC
        || symbols[3].type != URP_STT_FUNC || symbols[4].type != URP_STT_FUNC) {
        return URP_STATUS_UNSUPPORTED;
    }
    for (size_t index = 0U; index < 4U; ++index) {
        if (symbols[index + 1U].size == 0U
            || !urp_provider_find_load_range(
                image, image_size, &load_index, work,
                symbols[index + 1U].value, symbols[index + 1U].size,
                URP_PF_X, URP_PF_W, NULL, NULL)) {
            return URP_STATUS_UNSUPPORTED;
        }
        const uint8_t *entry = image + table_file_offset + index * sizeof(uint32_t);
        uint32_t raw_offset = urp_read_u32_le(entry);
        int64_t displacement = (raw_offset & UINT32_C(0x80000000)) != 0U
            ? (int64_t)raw_offset - INT64_C(0x100000000)
            : (int64_t)raw_offset;
        uint64_t target_address;
        if (displacement < 0) {
            uint64_t magnitude = (uint64_t)(-displacement);
            if (magnitude > symbols[0].value) return URP_STATUS_UNSUPPORTED;
            target_address = symbols[0].value - magnitude;
        } else if (!urp_checked_add_u64(symbols[0].value, (uint64_t)displacement, &target_address)) {
            return URP_STATUS_UNSUPPORTED;
        }
        if (target_address != symbols[index + 1U].value) return URP_STATUS_UNSUPPORTED;
    }
    out_facts->table_virtual_address = symbols[0].value;
    memcpy(out_facts->table_bytes, image + table_file_offset, sizeof(out_facts->table_bytes));
    return URP_STATUS_OK;
}

urp_status urp_host_external_provider_validate(
    const void *bytes,
    size_t image_size,
    const char *expected_soname,
    const char *expected_build_id_hex,
    urp_host_external_provider_facts *out_facts)
{
    urp_provider_work work = {
        .limit = urp_provider_work_limit(),
        .used = 0U,
#if defined(URP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS)
        .diagnostic_scope = URP_PROVIDER_WORK_DIAGNOSTICS_PROVIDER_PARSE,
#endif
    };
#if defined(URP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS)
    urp_provider_test_provider_parse_work_used = 0U;
    ++urp_provider_test_provider_parse_count;
#endif
    urp_status status = urp_host_external_provider_validate_impl(
        bytes, image_size, expected_soname, expected_build_id_hex, out_facts, &work);
#if defined(URP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS)
    urp_provider_test_provider_parse_work_used = work.used;
#endif
    return status;
}

urp_status urp_host_image_validate(
    const void *bytes,
    size_t image_size,
    size_t *out_dependency_count)
{
    int uses_provider = 0;
    uint64_t provider_got_virtual_address = 0U;
    return urp_host_image_validate_with_provider(
        bytes, image_size, NULL, out_dependency_count,
        &uses_provider, &provider_got_virtual_address);
}

