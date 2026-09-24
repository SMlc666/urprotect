#define _GNU_SOURCE

#include "urp/host_adapter.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

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
#define URP_DT_VERDEF UINT64_C(0x6ffffffc)
#define URP_DT_VERDEFNUM UINT64_C(0x6ffffffd)
#define URP_DT_VERNEED UINT64_C(0x6ffffffe)
#define URP_DT_VERNEEDNUM UINT64_C(0x6fffffff)
#define URP_DT_FLAGS_1 UINT64_C(0x6ffffffb)
#define URP_DT_AUXILIARY UINT64_C(0x7ffffffd)
#define URP_DT_FILTER UINT64_C(0x7fffffff)
#define URP_DF_BIND_NOW UINT64_C(0x8)
#define URP_DF_1_NOW UINT64_C(0x1)
#define URP_R_AARCH64_RELATIVE 1027U
#define URP_MEMFD_CLOEXEC 1U
#define URP_MEMFD_ALLOW_SEALING 2U
#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#endif
#ifndef F_GET_SEALS
#define F_GET_SEALS 1034
#endif
#ifndef F_SEAL_SEAL
#define F_SEAL_SEAL 0x0001
#endif
#ifndef F_SEAL_SHRINK
#define F_SEAL_SHRINK 0x0002
#endif
#ifndef F_SEAL_GROW
#define F_SEAL_GROW 0x0004
#endif
#ifndef F_SEAL_WRITE
#define F_SEAL_WRITE 0x0008
#endif
#define URP_REQUIRED_IMAGE_SEALS (F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL)
#define URP_MAX_PROGRAM_HEADERS 4096U
#define URP_MAX_DYNAMIC_ENTRIES (1U << 20)

typedef struct urp_fd_image {
    void *dl_handle;
    int fd;
} urp_fd_image;

typedef struct urp_dynamic_values {
    uint64_t strtab;
    uint64_t strsz;
    uint64_t needed_offset;
    uint64_t symtab;
    uint64_t syment;
    uint64_t rela;
    uint64_t relasz;
    uint64_t relaent;
    uint64_t jmprel;
    uint64_t pltrelsz;
    uint64_t pltrel;
    uint64_t relr;
    uint64_t relrsz;
    uint64_t relrent;
    int has_rela;
    int has_symtab;
    int has_syment;
    int has_strtab;
    int has_strsz;
    int has_needed;
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
        || file_size < 28U) {
        return URP_STATUS_UNSUPPORTED;
    }
    const uint8_t *note = image + file_offset;
    uint32_t namesz = urp_read_u32_le(note);
    uint32_t descsz = urp_read_u32_le(note + 4U);
    uint32_t type = urp_read_u32_le(note + 8U);
    if (namesz != 4U || descsz < 12U || type != URP_NOTE_GNU
        || memcmp(note + 12U, "GNU\0", 4U) != 0) {
        return URP_STATUS_UNSUPPORTED;
    }
    size_t property_offset = 16U;
    if (property_offset + 8U > file_size) {
        return URP_STATUS_UNSUPPORTED;
    }
    uint32_t property_type = urp_read_u32_le(note + property_offset);
    uint32_t property_size = urp_read_u32_le(note + property_offset + 4U);
    if (property_type != URP_GNU_PROPERTY_AARCH64_FEATURE_1_AND
        || property_size != 4U
        || property_offset + 8U + property_size > file_size) {
        return URP_STATUS_UNSUPPORTED;
    }
    uint32_t features = urp_read_u32_le(note + property_offset + 8U);
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
            || type == URP_R_AARCH64_JUMP_SLOT
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
    return urp_validate_rela_table(
        image,
        image_size,
        dynamic,
        dynamic->jmprel,
        dynamic->pltrelsz,
        program_header_offset,
        program_header_count);
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
        /* HostContext v1 defines only unversioned entry-symbol lookup. */
        case URP_DT_VERSYM:
        case URP_DT_VERDEF:
        case URP_DT_VERDEFNUM:
        case URP_DT_VERNEED:
        case URP_DT_VERNEEDNUM:
            if (!values.has_needed) {
                return URP_STATUS_UNSUPPORTED;
            }
            /* P3 dependency slice delegates libc symbol-version binding to dlopen. */
            break;
        case URP_DT_FLAGS:
            if (values.has_flags
                || (urp_read_u64_le(entry + 8U) & ~URP_DF_BIND_NOW) != 0U) {
                return URP_STATUS_UNSUPPORTED;
            }
            values.has_flags = 1;
            break;
        case URP_DT_FLAGS_1:
            if (values.has_flags_1
                || (urp_read_u64_le(entry + 8U) & ~URP_DF_1_NOW) != 0U) {
                return URP_STATUS_UNSUPPORTED;
            }
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
        const char *needed = (const char *)(image + string_offset + (size_t)values.needed_offset);
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

    urp_status status = urp_validate_rela(
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

static urp_status urp_validate_image(const void *bytes, size_t image_size)
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

static int urp_write_all(int fd, const void *bytes, size_t size)
{
    const uint8_t *source = (const uint8_t *)bytes;
    size_t offset = 0U;
    while (offset < size) {
        ssize_t written = write(fd, source + offset, size - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return 0;
        }
        offset += (size_t)written;
    }
    return 1;
}

static int urp_seal_image_fd(int fd)
{
    const int required_seals = URP_REQUIRED_IMAGE_SEALS;
    if (fcntl(fd, F_ADD_SEALS, required_seals) != 0) {
        return 0;
    }

    int seals = fcntl(fd, F_GET_SEALS);
    return seals >= 0 && (seals & required_seals) == required_seals;
}

static urp_status urp_adapter_load_image(
    void *userdata,
    const void *bytes,
    size_t size,
    uint32_t flags,
    urp_image_handle *out_handle)
{
    (void)userdata;
    if (out_handle == NULL) {
        return URP_STATUS_INVALID_ARGUMENT;
    }
    *out_handle = 0U;
    if ((flags & URP_LOAD_IMAGE_IMMUTABLE) == 0U) {
        return URP_STATUS_INVALID_ARGUMENT;
    }

    urp_status validation = urp_validate_image(bytes, size);
    if (validation != URP_STATUS_OK) {
        return validation;
    }

    long fd_result = syscall(
        SYS_memfd_create,
        "urprotect-host-image",
        URP_MEMFD_CLOEXEC | URP_MEMFD_ALLOW_SEALING);
    if (fd_result < 0 || fd_result > INT_MAX) {
        if (fd_result >= 0) {
            (void)close((int)fd_result);
        }
        return URP_STATUS_LOAD_FAILED;
    }
    int fd = (int)fd_result;
    if (!urp_write_all(fd, bytes, size)
        || fchmod(fd, S_IRUSR | S_IWUSR | S_IXUSR) != 0
        || lseek(fd, 0, SEEK_SET) < 0
        || !urp_seal_image_fd(fd)) {
        (void)close(fd);
        return URP_STATUS_LOAD_FAILED;
    }

    char fd_path[64];
    int path_size = snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    if (path_size < 0 || (size_t)path_size >= sizeof(fd_path)) {
        (void)close(fd);
        return URP_STATUS_LOAD_FAILED;
    }

    (void)dlerror();
    void *dl_handle = dlopen(fd_path, RTLD_NOW | RTLD_LOCAL);
    if (dl_handle == NULL) {
#if defined(URP_HOST_ADAPTER_TEST_DIAGNOSTICS)
        const char *loader_error = dlerror();
        (void)fprintf(
            stderr,
            "HostContext adapter dlopen failed: %s\n",
            loader_error != NULL ? loader_error : "unknown loader error");
#endif
        (void)close(fd);
        return URP_STATUS_LOAD_FAILED;
    }

    urp_fd_image *image = (urp_fd_image *)calloc(1U, sizeof(*image));
    if (image == NULL) {
        (void)dlclose(dl_handle);
        (void)close(fd);
        return URP_STATUS_LOAD_FAILED;
    }
    image->dl_handle = dl_handle;
    image->fd = fd;
    *out_handle = (urp_image_handle)(uintptr_t)image;
    return URP_STATUS_OK;
}

static urp_status urp_adapter_lookup_symbol(
    void *userdata,
    urp_image_handle handle,
    const char *name,
    const char *version,
    uintptr_t *out_address)
{
    (void)userdata;
    if (handle == 0U || name == NULL || version != NULL || out_address == NULL) {
        return URP_STATUS_INVALID_ARGUMENT;
    }

    urp_fd_image *image = (urp_fd_image *)(uintptr_t)handle;
    (void)dlerror();
    void *symbol = dlsym(image->dl_handle, name);
    const char *error = dlerror();
    if (symbol == NULL || error != NULL) {
        return URP_STATUS_SYMBOL_NOT_FOUND;
    }
    *out_address = (uintptr_t)symbol;
    return URP_STATUS_OK;
}

static urp_status urp_adapter_release_image(void *userdata, urp_image_handle handle)
{
    (void)userdata;
    if (handle == 0U) {
        return URP_STATUS_INVALID_ARGUMENT;
    }

    urp_fd_image *image = (urp_fd_image *)(uintptr_t)handle;
    int dl_result = dlclose(image->dl_handle);
    int close_result = close(image->fd);
    free(image);
    return dl_result == 0 && close_result == 0
        ? URP_STATUS_OK
        : URP_STATUS_LOAD_FAILED;
}

int urp_host_adapter_image_is_sealed(urp_image_handle handle)
{
    if (handle == 0U) {
        return 0;
    }

    const urp_fd_image *image = (const urp_fd_image *)(uintptr_t)handle;
    int seals = fcntl(image->fd, F_GET_SEALS);
    return seals >= 0 && (seals & URP_REQUIRED_IMAGE_SEALS) == URP_REQUIRED_IMAGE_SEALS;
}

static urp_status urp_adapter_emit_diagnostic(
    void *userdata,
    uint32_t code,
    const char *message)
{
    (void)userdata;
    (void)code;
    (void)message;
    return URP_STATUS_OK;
}

void urp_host_adapter_init(urp_host_adapter_v1 *adapter)
{
    if (adapter == NULL) {
        return;
    }
    memset(adapter, 0, sizeof(*adapter));
    adapter->context.abi_version = URP_HOST_ABI_VERSION;
    adapter->context.struct_size = sizeof(adapter->context);
    adapter->context.capabilities = URP_HOST_CAP_LOAD_IMAGE
        | URP_HOST_CAP_LOOKUP_SYMBOL
        | URP_HOST_CAP_RELEASE_IMAGE
        | URP_HOST_CAP_EMIT_DIAGNOSTIC;
    adapter->context.userdata = adapter;
    adapter->context.load_image = urp_adapter_load_image;
    adapter->context.lookup_symbol = urp_adapter_lookup_symbol;
    adapter->context.release_image = urp_adapter_release_image;
    adapter->context.emit_diagnostic = urp_adapter_emit_diagnostic;
}
