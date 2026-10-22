#define _GNU_SOURCE

#include "native_process_identity.h"

#include <elf.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define TEST_ELF_CAPACITY (64U * 1024U)
#define TEST_BASE_ADDRESS UINT64_C(0x400000)
#define TEST_DEVICE_MAJOR 8U
#define TEST_DEVICE_MINOR 1U
#define TEST_INODE UINT64_C(1001)

typedef struct {
    uint8_t bytes[TEST_ELF_CAPACITY];
    size_t size;
} test_elf;

static int make_elf(test_elf *result, uint64_t page_size, size_t load_count, int duplicate, int partial_overlap)
{
    Elf64_Ehdr header = {0};
    Elf64_Phdr loads[2] = {{0}};
    size_t image_size;
    if (result == NULL || page_size == 0U || page_size > TEST_ELF_CAPACITY / 4U || load_count == 0U || load_count > 2U) return 0;
    image_size = (size_t)(page_size * 2U);
    if (image_size > sizeof(result->bytes)) return 0;
    memset(result, 0, sizeof(*result));

    memcpy(header.e_ident, ELFMAG, SELFMAG);
    header.e_ident[EI_CLASS] = ELFCLASS64;
    header.e_ident[EI_DATA] = ELFDATA2LSB;
    header.e_ident[EI_VERSION] = EV_CURRENT;
    header.e_type = ET_DYN;
    header.e_machine = EM_AARCH64;
    header.e_version = EV_CURRENT;
    header.e_ehsize = sizeof(header);
    header.e_phoff = sizeof(header);
    header.e_phentsize = sizeof(Elf64_Phdr);
    header.e_phnum = (Elf64_Half)load_count;

    loads[0].p_type = PT_LOAD;
    loads[0].p_flags = PF_R | PF_X;
    loads[0].p_offset = 0U;
    loads[0].p_vaddr = 0U;
    loads[0].p_filesz = (Elf64_Xword)image_size;
    loads[0].p_memsz = (Elf64_Xword)image_size;
    loads[0].p_align = page_size;
    if (load_count == 2U) {
        if (duplicate) {
            loads[1] = loads[0];
        } else if (partial_overlap) {
            loads[1].p_type = PT_LOAD;
            loads[1].p_flags = PF_R;
            loads[1].p_offset = page_size;
            loads[1].p_vaddr = page_size;
            loads[1].p_filesz = page_size;
            loads[1].p_memsz = page_size;
            loads[1].p_align = page_size;
        } else {
            return 0;
        }
    }
    memcpy(result->bytes, &header, sizeof(header));
    memcpy(result->bytes + sizeof(header), loads, load_count * sizeof(loads[0]));
    result->size = image_size;
    return 1;
}

static Elf64_Phdr make_load(
    uint64_t page_size,
    uint64_t file_offset,
    uint64_t virtual_address,
    uint64_t file_size,
    uint64_t memory_size,
    uint32_t flags)
{
    Elf64_Phdr load = {0};
    load.p_type = PT_LOAD;
    load.p_flags = flags;
    load.p_offset = file_offset;
    load.p_vaddr = virtual_address;
    load.p_filesz = file_size;
    load.p_memsz = memory_size;
    load.p_align = page_size;
    return load;
}

static int make_elf_with_loads(
    test_elf *result,
    uint64_t page_size,
    size_t file_pages,
    const Elf64_Phdr *loads,
    size_t load_count)
{
    Elf64_Ehdr header = {0};
    size_t image_size;
    if (result == NULL || loads == NULL || page_size == 0U
        || page_size > (uint64_t)sizeof(result->bytes)
        || file_pages == 0U || file_pages > sizeof(result->bytes) / (size_t)page_size
        || load_count == 0U || load_count > 2U) return 0;
    image_size = file_pages * (size_t)page_size;
    memset(result, 0, sizeof(*result));
    memcpy(header.e_ident, ELFMAG, SELFMAG);
    header.e_ident[EI_CLASS] = ELFCLASS64;
    header.e_ident[EI_DATA] = ELFDATA2LSB;
    header.e_ident[EI_VERSION] = EV_CURRENT;
    header.e_type = ET_DYN;
    header.e_machine = EM_AARCH64;
    header.e_version = EV_CURRENT;
    header.e_ehsize = sizeof(header);
    header.e_phoff = sizeof(header);
    header.e_phentsize = sizeof(Elf64_Phdr);
    header.e_phnum = (Elf64_Half)load_count;
    memcpy(result->bytes, &header, sizeof(header));
    memcpy(result->bytes + sizeof(header), loads, load_count * sizeof(loads[0]));
    result->size = image_size;
    return 1;
}

static int append_map_at(
    char *buffer,
    size_t capacity,
    size_t *used,
    uint64_t page_size,
    uint64_t virtual_first_page,
    uint64_t file_first_page,
    uint64_t mapped_pages,
    const char *permissions)
{
    int length;
    uint64_t map_start = TEST_BASE_ADDRESS + virtual_first_page * page_size;
    uint64_t map_end = map_start + mapped_pages * page_size;
    uint64_t file_offset = file_first_page * page_size;
    if (*used >= capacity) return 0;
    length = snprintf(
        buffer + *used,
        capacity - *used,
        "%016" PRIx64 "-%016" PRIx64 " %s %08" PRIx64 " %02x:%02x %" PRIu64 " /lib/ld-musl-aarch64.so.1\n",
        map_start,
        map_end,
        permissions,
        file_offset,
        TEST_DEVICE_MAJOR,
        TEST_DEVICE_MINOR,
        TEST_INODE);
    if (length < 0 || (size_t)length >= capacity - *used) return 0;
    *used += (size_t)length;
    return 1;
}

static int append_map(
    char *buffer,
    size_t capacity,
    size_t *used,
    uint64_t page_size,
    uint64_t first_page,
    uint64_t mapped_pages,
    const char *permissions)
{
    return append_map_at(
        buffer,
        capacity,
        used,
        page_size,
        first_page,
        first_page,
        mapped_pages,
        permissions);
}

static int verify(const test_elf *elf, const char *maps, int expected)
{
    int observed = urp_native_process_identity_test_verify_maps(
        (const uint8_t *)maps,
        strlen(maps),
        "/lib/ld-musl-aarch64.so.1",
        elf->bytes,
        elf->size,
        1);
    return observed == expected;
}

static int test_musl_combined_loader_relro_splits(uint64_t page_size)
{
    test_elf elf;
    Elf64_Ehdr header;
    Elf64_Phdr relro = {0};
    char maps[1024] = {0};
    size_t used = 0U;
    if (!make_elf(&elf, page_size, 1U, 0, 0)) return 0;
    memcpy(&header, elf.bytes, sizeof(header));
    header.e_phnum = 2U;
    relro.p_type = PT_GNU_RELRO;
    relro.p_flags = PF_R;
    relro.p_offset = page_size;
    relro.p_vaddr = page_size;
    relro.p_filesz = page_size;
    relro.p_memsz = page_size;
    relro.p_align = 1U;
    memcpy(elf.bytes, &header, sizeof(header));
    memcpy(elf.bytes + sizeof(header) + sizeof(Elf64_Phdr), &relro, sizeof(relro));
    if (!append_map(maps, sizeof(maps), &used, page_size, 0U, 1U, "r-xp")
        || !append_map(maps, sizeof(maps), &used, page_size, 1U, 1U, "r--p")
        || !verify(&elf, maps, 1)) {
        (void)fprintf(stderr, "FAIL native identity valid musl combined-loader RELRO split\n");
        return 0;
    }
    (void)printf("PASS native identity valid musl combined-loader RELRO split\n");
    return 1;
}

static int test_duplicate_full_pt_load_rejected(uint64_t page_size)
{
    test_elf elf;
    char maps[512] = {0};
    size_t used = 0U;
    if (!make_elf(&elf, page_size, 2U, 1, 0)
        || !append_map(maps, sizeof(maps), &used, page_size, 0U, 1U, "r-xp")
        || !append_map(maps, sizeof(maps), &used, page_size, 1U, 1U, "r-xp")
        || !verify(&elf, maps, 0)) {
        (void)fprintf(stderr, "FAIL native identity duplicate full PT_LOAD owner rejection\n");
        return 0;
    }
    (void)printf("PASS native identity duplicate full PT_LOAD owner rejection\n");
    return 1;
}

static int test_partial_pt_load_overlap_rejected(uint64_t page_size)
{
    test_elf elf;
    char maps[512] = {0};
    size_t used = 0U;
    if (!make_elf(&elf, page_size, 2U, 0, 1)
        || !append_map(maps, sizeof(maps), &used, page_size, 0U, 2U, "r-xp")
        || !verify(&elf, maps, 0)) {
        (void)fprintf(stderr, "FAIL native identity partial PT_LOAD overlap rejection\n");
        return 0;
    }
    (void)printf("PASS native identity partial PT_LOAD overlap rejection\n");
    return 1;
}

static int expect_virtual_overlap_rejected(
    const char *name,
    uint64_t page_size,
    const Elf64_Phdr loads[2],
    uint64_t mapped_pages)
{
    test_elf elf;
    char maps[1024] = {0};
    size_t used = 0U;
    if (!make_elf_with_loads(&elf, page_size, 3U, loads, 2U)
        || !append_map(maps, sizeof(maps), &used, page_size, 0U, mapped_pages, "r-xp")
        || !verify(&elf, maps, 0)) {
        (void)fprintf(stderr, "FAIL native identity %s virtual-memory overlap rejection\n", name);
        return 0;
    }
    (void)printf("PASS native identity %s virtual-memory overlap rejection\n", name);
    return 1;
}

static int test_review_virtual_overlap(uint64_t page_size)
{
    Elf64_Phdr loads[2];
    loads[0] = make_load(page_size, 0U, 0U, 2U * page_size, 2U * page_size, PF_R | PF_X);
    loads[1] = make_load(page_size, 2U * page_size, 0U, page_size, page_size, PF_R);
    return expect_virtual_overlap_rejected("review-example", page_size, loads, 1U);
}

static int test_full_and_partial_virtual_overlaps(uint64_t page_size)
{
    Elf64_Phdr loads[2];
    loads[0] = make_load(page_size, 0U, 0U, 2U * page_size, 2U * page_size, PF_R | PF_X);
    loads[1] = make_load(page_size, 2U * page_size, 0U, page_size, 2U * page_size, PF_R);
    if (!expect_virtual_overlap_rejected("full-file-disjoint", page_size, loads, 2U)) return 0;
    loads[1] = make_load(page_size, 2U * page_size, page_size, page_size, page_size, PF_R);
    return expect_virtual_overlap_rejected("partial-file-disjoint", page_size, loads, 2U);
}

static int test_bss_virtual_overlap(uint64_t page_size)
{
    Elf64_Phdr loads[2];
    loads[0] = make_load(page_size, 0U, 0U, 2U * page_size, 2U * page_size, PF_R | PF_X);
    loads[1] = make_load(page_size, 2U * page_size, 0U, 0U, page_size, PF_R);
    return expect_virtual_overlap_rejected("zero-filesz-bss", page_size, loads, 1U);
}

static int test_overflowing_page_rounded_memory_extent_rejected(uint64_t page_size)
{
    Elf64_Phdr loads[2];
    loads[0] = make_load(page_size, 0U, 0U, 2U * page_size, 2U * page_size, PF_R | PF_X);
    loads[1] = make_load(
        1U,
        2U * page_size,
        UINT64_MAX - page_size + 1U,
        0U,
        page_size - 2U,
        PF_R);
    if (!expect_virtual_overlap_rejected("overflowing-memory-end", page_size, loads, 1U)) return 0;
    (void)printf("PASS native identity overflowing rounded PT_LOAD memory extent fails closed\n");
    return 1;
}

static int test_half_open_adjacent_virtual_load_pages(uint64_t page_size)
{
    test_elf elf;
    Elf64_Phdr loads[2];
    char maps[1024] = {0};
    size_t used = 0U;
    loads[0] = make_load(page_size, 0U, 0U, page_size, page_size, PF_R | PF_X);
    loads[1] = make_load(page_size, 2U * page_size, page_size, page_size, page_size, PF_R | PF_X);
    if (!make_elf_with_loads(&elf, page_size, 3U, loads, 2U)
        || !append_map_at(maps, sizeof(maps), &used, page_size, 0U, 0U, 1U, "r-xp")
        || !append_map_at(maps, sizeof(maps), &used, page_size, 1U, 2U, 1U, "r-xp")
        || !verify(&elf, maps, 1)) {
        (void)fprintf(stderr, "FAIL native identity adjacent half-open PT_LOAD pages remain valid\n");
        return 0;
    }
    (void)printf("PASS native identity adjacent half-open PT_LOAD pages remain valid\n");
    return 1;
}

int main(void)
{
    long page_size_long = sysconf(_SC_PAGESIZE);
    uint64_t page_size;
    if (page_size_long <= 0) {
        (void)fprintf(stderr, "FAIL native identity test cannot determine page size\n");
        return 1;
    }
    page_size = (uint64_t)page_size_long;
    if ((page_size & (page_size - 1U)) != 0U
        || page_size > TEST_ELF_CAPACITY / 4U
        || (TEST_BASE_ADDRESS & (page_size - 1U)) != 0U) {
        (void)fprintf(stderr, "FAIL native identity test page size is not a supported power of two\n");
        return 1;
    }
    if (!test_musl_combined_loader_relro_splits(page_size)
        || !test_duplicate_full_pt_load_rejected(page_size)
        || !test_partial_pt_load_overlap_rejected(page_size)
        || !test_review_virtual_overlap(page_size)
        || !test_full_and_partial_virtual_overlaps(page_size)
        || !test_bss_virtual_overlap(page_size)
        || !test_overflowing_page_rounded_memory_extent_rejected(page_size)
        || !test_half_open_adjacent_virtual_load_pages(page_size)) return 1;
    return 0;
}
