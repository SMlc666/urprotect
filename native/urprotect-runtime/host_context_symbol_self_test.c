#include "urp/host_adapter.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint16_t read_u16(const uint8_t *p)
{
    return (uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8U);
}

static uint32_t read_u32(const uint8_t *p)
{
    return (uint32_t)p[0]
        | ((uint32_t)p[1] << 8U)
        | ((uint32_t)p[2] << 16U)
        | ((uint32_t)p[3] << 24U);
}

static uint64_t read_u64(const uint8_t *p)
{
    uint64_t value = 0U;
    for (size_t i = 0U; i < 8U; ++i) {
        value |= (uint64_t)p[i] << (i * 8U);
    }
    return value;
}

static void write_u64(uint8_t *p, uint64_t value)
{
    for (size_t i = 0U; i < 8U; ++i) {
        p[i] = (uint8_t)(value >> (i * 8U));
    }
}

static int read_file(const char *path, uint8_t **bytes_out, size_t *size_out)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL || fseek(file, 0L, SEEK_END) != 0) {
        if (file != NULL) {
            fclose(file);
        }
        return 0;
    }
    long length = ftell(file);
    if (length <= 0L || fseek(file, 0L, SEEK_SET) != 0) {
        fclose(file);
        return 0;
    }
    uint8_t *bytes = (uint8_t *)malloc((size_t)length);
    if (bytes == NULL || fread(bytes, 1U, (size_t)length, file) != (size_t)length) {
        free(bytes);
        fclose(file);
        return 0;
    }
    fclose(file);
    *bytes_out = bytes;
    *size_out = (size_t)length;
    return 1;
}

static int find_rela(uint8_t *image, size_t image_size, size_t *offset_out)
{
    if (image_size < 64U || read_u16(image + 54U) != 56U) {
        return 0;
    }
    uint64_t phoff = read_u64(image + 32U);
    uint16_t phnum = read_u16(image + 56U);
    uint64_t dynamic_offset = 0U;
    uint64_t dynamic_size = 0U;
    uint64_t rela_address = 0U;
    uint64_t rela_size = 0U;
    for (uint16_t i = 0U; i < phnum; ++i) {
        const uint8_t *ph = image + (size_t)(phoff + (uint64_t)i * 56U);
        if (read_u32(ph) == 2U) {
            dynamic_offset = read_u64(ph + 8U);
            dynamic_size = read_u64(ph + 32U);
        }
    }
    if (dynamic_offset + dynamic_size > image_size || dynamic_size % 16U != 0U) {
        return 0;
    }
    for (uint64_t offset = 0U; offset < dynamic_size; offset += 16U) {
        const uint8_t *entry = image + (size_t)(dynamic_offset + offset);
        uint64_t tag = read_u64(entry);
        if (tag == 0U) {
            break;
        }
        if (tag == 7U) {
            rela_address = read_u64(entry + 8U);
        } else if (tag == 8U) {
            rela_size = read_u64(entry + 8U);
        }
    }
    if (rela_address == 0U || rela_size < 24U) {
        return 0;
    }
    for (uint16_t i = 0U; i < phnum; ++i) {
        const uint8_t *ph = image + (size_t)(phoff + (uint64_t)i * 56U);
        if (read_u32(ph) != 1U) {
            continue;
        }
        uint64_t vaddr = read_u64(ph + 16U);
        uint64_t file_offset = read_u64(ph + 8U);
        uint64_t file_size = read_u64(ph + 32U);
        if (rela_address >= vaddr && rela_address - vaddr < file_size
            && rela_size <= file_size - (rela_address - vaddr)) {
            uint64_t file_rela = file_offset + (rela_address - vaddr);
            if (file_rela + 24U <= image_size && file_rela <= SIZE_MAX) {
                *offset_out = (size_t)file_rela;
                return 1;
            }
        }
    }
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
        || handle == 0U
        || adapter.context.release_image(adapter.context.userdata, handle) != URP_STATUS_OK) {
        free(source);
        return 1;
    }

    size_t rela_offset = 0U;
    if (!find_rela(source, source_size, &rela_offset)) {
        free(source);
        return 1;
    }
    uint64_t info = read_u64(source + rela_offset + 8U);
    write_u64(source + rela_offset + 8U, (info & UINT64_C(0xffffffff00000000)) | UINT64_C(0xdead));
    handle = UINT64_C(0xfeedface);
    urp_status status = adapter.context.load_image(
        adapter.context.userdata,
        source,
        source_size,
        URP_LOAD_IMAGE_IMMUTABLE,
        &handle);
    free(source);
    if (status != URP_STATUS_UNSUPPORTED || handle != 0U) {
        return 1;
    }
    puts("HostContext symbolic relocation self-test: PASS");
    return 0;
}
