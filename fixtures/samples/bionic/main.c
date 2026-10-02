#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

extern uint64_t urp_transform_target(uint64_t left, uint64_t right);

int main(void)
{
    if (urp_transform_target(7, 4) != 26 || urp_transform_target(0, 4) != 4) {
        return 1;
    }
    printf("urprotect-fixture:bionic:%ld\n", (long)sysconf(_SC_PAGESIZE));
    return 0;
}
