#include "urp/host_adapter.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DT_NULL 0U
#define DT_NEEDED 1U
#define DT_PLTRELSZ 2U
#define DT_SYMTAB 6U
#define DT_STRTAB 5U
#define DT_STRSZ 10U
#define DT_FLAGS 30U
#define DT_FLAGS_1 UINT64_C(0x6ffffffb)
#define DT_SYMBOLIC 16U
#define DT_JMPREL 23U
#define DT_PLTREL 20U
#define DT_RELA 7U
#define DT_RELASZ 8U
#define DT_VERSYM UINT64_C(0x6ffffff0)
#define DF_BIND_NOW UINT64_C(8)
#define PF_W UINT32_C(2)
#define PT_LOAD UINT32_C(1)
#define PT_DYNAMIC UINT32_C(2)
#define R_AARCH64_GLOB_DAT UINT64_C(1025)
#define R_AARCH64_JUMP_SLOT UINT64_C(1026)

typedef struct dynamic_table {
    size_t file_offset;
    size_t file_size;
} dynamic_table;

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
    size_t size = (size_t)length;
    if (fread(bytes, 1U, size, file) != size || ferror(file) != 0) {
        free(bytes);
        (void)fclose(file);
        return 0;
    }
    (void)fclose(file);
    *bytes_out = bytes;
    *size_out = size;
    return 1;
}

static int find_dynamic_table(
    const uint8_t *image,
    size_t image_size,
    dynamic_table *table_out)
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

    int found = 0;
    for (uint16_t index = 0U; index < program_header_count; ++index) {
        const uint8_t *header = image
            + (size_t)(program_header_offset + (uint64_t)index * 56U);
        if (read_u32(header) != PT_DYNAMIC) {
            continue;
        }
        if (found != 0) {
            return 0;
        }
        uint64_t offset = read_u64(header + 8U);
        uint64_t size = read_u64(header + 32U);
        if (offset > (uint64_t)image_size
            || size > (uint64_t)image_size - offset
            || size % 16U != 0U) {
            return 0;
        }
        table_out->file_offset = (size_t)offset;
        table_out->file_size = (size_t)size;
        found = 1;
    }
    return found != 0;
}

static int locate_dynamic_tag(
    uint8_t *image,
    size_t image_size,
    uint64_t wanted_tag,
    size_t *tag_offset_out,
    size_t *value_offset_out)
{
    dynamic_table table;
    if (!find_dynamic_table(image, image_size, &table)) {
        return 0;
    }

    size_t entry_count = table.file_size / 16U;
    for (size_t index = 0U; index < entry_count; ++index) {
        size_t entry_offset = table.file_offset + index * 16U;
        uint8_t *entry = image + entry_offset;
        uint64_t tag = read_u64(entry);
        if (tag == wanted_tag) {
            if (tag_offset_out != NULL) {
                *tag_offset_out = entry_offset;
            }
            if (value_offset_out != NULL) {
                *value_offset_out = entry_offset + 8U;
            }
            return 1;
        }
        if (tag == DT_NULL) {
            return 0;
        }
    }
    return 0;
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
        if (read_u32(header) != PT_LOAD) {
            continue;
        }

        uint64_t segment_virtual_address = read_u64(header + 16U);
        uint64_t segment_file_offset = read_u64(header + 8U);
        uint64_t segment_file_size = read_u64(header + 32U);
        if (segment_file_offset > (uint64_t)image_size
            || segment_file_size > (uint64_t)image_size - segment_file_offset
            || virtual_address < segment_virtual_address) {
            continue;
        }
        uint64_t delta = virtual_address - segment_virtual_address;
        if (delta > segment_file_size
            || (uint64_t)length > segment_file_size - delta) {
            continue;
        }
        uint64_t file_offset = segment_file_offset + delta;
        if ((uint64_t)length > (uint64_t)image_size - file_offset) {
            continue;
        }
        *file_offset_out = (size_t)file_offset;
        return 1;
    }
    return 0;
}

static int locate_plt(
    uint8_t *image,
    size_t image_size,
    size_t *rela_offset_out,
    size_t *symbol_offset_out,
    size_t *terminator_offset_out,
    uint64_t *target_address_out)
{
    size_t jmprel_value_offset;
    size_t pltrelsz_value_offset;
    size_t symtab_value_offset;
    size_t terminator_offset;
    if (!locate_dynamic_tag(image, image_size, DT_JMPREL, NULL, &jmprel_value_offset)
        || !locate_dynamic_tag(
            image, image_size, DT_PLTRELSZ, NULL, &pltrelsz_value_offset)
        || !locate_dynamic_tag(image, image_size, DT_SYMTAB, NULL, &symtab_value_offset)
        || !locate_dynamic_tag(image, image_size, DT_NULL, &terminator_offset, NULL)) {
        return 0;
    }

    uint64_t table_address = read_u64(image + jmprel_value_offset);
    uint64_t table_size = read_u64(image + pltrelsz_value_offset);
    uint64_t symbol_table_address = read_u64(image + symtab_value_offset);
    if (table_size < 24U || table_size % 24U != 0U || table_size > SIZE_MAX) {
        return 0;
    }
    size_t rela_offset;
    if (!virtual_to_file(image, image_size, table_address, (size_t)table_size, &rela_offset)) {
        return 0;
    }

    uint64_t info = read_u64(image + rela_offset + 8U);
    uint64_t symbol_index = info >> 32U;
    uint64_t symbol_delta = symbol_index * 24U;
    if (symbol_index == 0U || symbol_delta > UINT64_MAX - symbol_table_address) {
        return 0;
    }
    size_t symbol_offset;
    if (!virtual_to_file(
            image,
            image_size,
            symbol_table_address + symbol_delta,
            24U,
            &symbol_offset)) {
        return 0;
    }

    *rela_offset_out = rela_offset;
    *symbol_offset_out = symbol_offset;
    *terminator_offset_out = terminator_offset;
    *target_address_out = read_u64(image + rela_offset);
    return 1;
}

static int locate_rela_dyn(
    uint8_t *image,
    size_t image_size,
    size_t *rela_offset_out)
{
    size_t rela_value_offset;
    size_t rela_size_value_offset;
    if (!locate_dynamic_tag(image, image_size, DT_RELA, NULL, &rela_value_offset)
        || !locate_dynamic_tag(image, image_size, DT_RELASZ, NULL, &rela_size_value_offset)) {
        return 0;
    }

    uint64_t table_address = read_u64(image + rela_value_offset);
    uint64_t table_size = read_u64(image + rela_size_value_offset);
    if (table_size < 24U || table_size % 24U != 0U || table_size > SIZE_MAX) {
        return 0;
    }
    return virtual_to_file(image, image_size, table_address, (size_t)table_size, rela_offset_out);
}

static int locate_target_load_flags(
    uint8_t *image,
    size_t image_size,
    uint64_t target_address,
    size_t *flags_offset_out)
{
    uint64_t program_header_offset = read_u64(image + 32U);
    uint16_t program_header_count = read_u16(image + 56U);
    if (program_header_offset > (uint64_t)image_size
        || (uint64_t)program_header_count * 56U
            > (uint64_t)image_size - program_header_offset) {
        return 0;
    }
    for (uint16_t index = 0U; index < program_header_count; ++index) {
        size_t header_offset = (size_t)(program_header_offset + (uint64_t)index * 56U);
        uint8_t *header = image + header_offset;
        if (read_u32(header) != PT_LOAD) {
            continue;
        }
        uint64_t segment_virtual_address = read_u64(header + 16U);
        uint64_t segment_memory_size = read_u64(header + 40U);
        if (target_address >= segment_virtual_address
            && target_address - segment_virtual_address < segment_memory_size) {
            *flags_offset_out = header_offset + 4U;
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
    urp_image_handle handle = UINT64_C(0xfeedface);
    urp_status status = adapter->context.load_image(
        adapter->context.userdata,
        image,
        image_size,
        URP_LOAD_IMAGE_IMMUTABLE,
        &handle);
    return status == expected_status && handle == 0U;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        return 2;
    }

    uint8_t *source = NULL;
    size_t source_size = 0U;
    if (!read_file(argv[1], &source, &source_size)) {
        return 1;
    }

    urp_host_adapter_v1 adapter;
    urp_host_adapter_init(&adapter);
    urp_image_handle handle = 0U;
    if (adapter.context.load_image(
            adapter.context.userdata,
            source,
            source_size,
            URP_LOAD_IMAGE_IMMUTABLE,
            &handle) != URP_STATUS_OK
        || handle == 0U) {
        free(source);
        return 1;
    }

    uintptr_t entry_address = 0U;
    if (adapter.context.lookup_symbol(
            adapter.context.userdata,
            handle,
            "urp_entry",
            NULL,
            &entry_address) != URP_STATUS_OK
        || entry_address == 0U
        || sizeof(urp_entry_fn) != sizeof(entry_address)) {
        (void)adapter.context.release_image(adapter.context.userdata, handle);
        free(source);
        return 1;
    }
    urp_entry_fn entry = NULL;
    memcpy(&entry, &entry_address, sizeof(entry));
    const char *entry_argv[] = {"plt-fixture", NULL};
    urp_launch_args_v1 args = {
        .abi_version = URP_HOST_ABI_VERSION,
        .struct_size = sizeof(urp_launch_args_v1),
        .argc = 1U,
        .argv = entry_argv,
        .envp = NULL,
    };
    int32_t entry_status = entry(&adapter.context, &args);
    if (entry_status != 53
        || adapter.context.release_image(adapter.context.userdata, handle) != URP_STATUS_OK) {
        free(source);
        return 1;
    }

    size_t rela_offset;
    size_t symbol_offset;
    size_t terminator_offset;
    size_t rela_dyn_offset;
    uint64_t target_address;
    if (!locate_plt(
            source,
            source_size,
            &rela_offset,
            &symbol_offset,
            &terminator_offset,
            &target_address)
        || (uint32_t)read_u64(source + rela_offset + 8U) != R_AARCH64_JUMP_SLOT
        || !locate_rela_dyn(source, source_size, &rela_dyn_offset)
        || (uint32_t)read_u64(source + rela_dyn_offset + 8U) != R_AARCH64_GLOB_DAT) {
        free(source);
        return 1;
    }

    size_t target_flags_offset;
    if (!locate_target_load_flags(source, source_size, target_address, &target_flags_offset)) {
        free(source);
        return 1;
    }

    uint8_t *mutant = (uint8_t *)malloc(source_size);
    if (mutant == NULL) {
        free(source);
        return 1;
    }

    /* Strong bindings, non-functions, non-default visibility, and definitions are out of scope. */
    memcpy(mutant, source, source_size);
    mutant[symbol_offset + 4U] = (uint8_t)((mutant[symbol_offset + 4U] & 0x0fU) | 0x10U);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_UNSUPPORTED)) {
        goto failed;
    }

    memcpy(mutant, source, source_size);
    mutant[symbol_offset + 4U] = (uint8_t)((mutant[symbol_offset + 4U] & 0xf0U) | 1U);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_UNSUPPORTED)) {
        goto failed;
    }

    memcpy(mutant, source, source_size);
    mutant[symbol_offset + 5U] = (uint8_t)((mutant[symbol_offset + 5U] & 0xfcU) | 2U);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_UNSUPPORTED)) {
        goto failed;
    }

    memcpy(mutant, source, source_size);
    mutant[symbol_offset + 5U] |= 0x80U;
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_UNSUPPORTED)) {
        goto failed;
    }

    memcpy(mutant, source, source_size);
    write_u16(mutant + symbol_offset + 6U, 1U);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_UNSUPPORTED)) {
        goto failed;
    }

    /* JUMP_SLOT belongs only to the checked PLT table, never ordinary DT_RELA. */
    memcpy(mutant, source, source_size);
    write_u64(mutant + rela_dyn_offset + 8U,
        (read_u64(mutant + rela_dyn_offset + 8U) & UINT64_C(0xffffffff00000000))
            | R_AARCH64_JUMP_SLOT);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_UNSUPPORTED)) {
        goto failed;
    }

    /* PLT relocation type, target alignment, target permissions, and range are exact. */
    memcpy(mutant, source, source_size);
    write_u64(mutant + rela_offset + 8U,
        (read_u64(mutant + rela_offset + 8U) & UINT64_C(0xffffffff00000000))
            | R_AARCH64_GLOB_DAT);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_UNSUPPORTED)) {
        goto failed;
    }

    memcpy(mutant, source, source_size);
    write_u64(mutant + rela_offset, target_address + 1U);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_UNSUPPORTED)) {
        goto failed;
    }

    memcpy(mutant, source, source_size);
    write_u32(mutant + target_flags_offset,
        read_u32(mutant + target_flags_offset) & ~PF_W);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_UNSUPPORTED)) {
        goto failed;
    }

    size_t jmprel_value_offset;
    if (!locate_dynamic_tag(
            source, source_size, DT_JMPREL, NULL, &jmprel_value_offset)) {
        goto failed;
    }
    memcpy(mutant, source, source_size);
    write_u64(mutant + jmprel_value_offset, UINT64_MAX - 7U);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_LOAD_FAILED)) {
        goto failed;
    }

    /* Dependencies, version tags, partial tuples, and symbolic lookup are separate contracts. */
    memcpy(mutant, source, source_size);
    write_u64(mutant + terminator_offset, DT_NEEDED);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_UNSUPPORTED)) {
        goto failed;
    }

    memcpy(mutant, source, source_size);
    write_u64(mutant + terminator_offset, DT_VERSYM);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_UNSUPPORTED)) {
        goto failed;
    }

    size_t pltrel_tag_offset;
    size_t pltrel_value_offset;
    if (!locate_dynamic_tag(
            source, source_size, DT_PLTREL, &pltrel_tag_offset, &pltrel_value_offset)) {
        goto failed;
    }
    memcpy(mutant, source, source_size);
    write_u64(mutant + pltrel_tag_offset, DT_NULL);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_UNSUPPORTED)) {
        goto failed;
    }

    memcpy(mutant, source, source_size);
    write_u64(mutant + pltrel_value_offset, DT_RELA + 10U);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_UNSUPPORTED)) {
        goto failed;
    }

    size_t flags_value_offset;
    size_t flags1_value_offset;
    if (!locate_dynamic_tag(source, source_size, DT_FLAGS, NULL, &flags_value_offset)
        || !locate_dynamic_tag(
            source, source_size, DT_FLAGS_1, NULL, &flags1_value_offset)) {
        goto failed;
    }
    memcpy(mutant, source, source_size);
    write_u64(mutant + flags_value_offset, 0U);
    write_u64(mutant + flags1_value_offset, 0U);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_UNSUPPORTED)) {
        goto failed;
    }

    memcpy(mutant, source, source_size);
    write_u64(mutant + terminator_offset, DT_JMPREL);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_LOAD_FAILED)) {
        goto failed;
    }

    memcpy(mutant, source, source_size);
    write_u64(mutant + terminator_offset, DT_SYMBOLIC);
    if (!expect_reject(&adapter, mutant, source_size, URP_STATUS_UNSUPPORTED)) {
        goto failed;
    }

    free(mutant);
    free(source);
    puts("HostContext weak JUMP_SLOT self-test: PASS");
    return 0;

failed:
    free(mutant);
    free(source);
    return 1;
}
