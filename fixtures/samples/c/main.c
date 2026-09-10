#include <stdint.h>
#include <stdio.h>

static uint32_t mix(uint32_t value) {
    value ^= value >> 16;
    value *= 0x45d9f3bU;
    value ^= value >> 16;
    return value;
}

int main(void) {
    const uint32_t value = mix(0x13579bdfU);
    puts("urprotect-fixture:c");
    printf("checksum=%08x\n", value);
    return value == 0 ? 1 : 0;
}
