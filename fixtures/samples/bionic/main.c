#include <stdio.h>
#include <unistd.h>

int main(void)
{
    printf("urprotect-fixture:bionic:%ld\n", (long)sysconf(_SC_PAGESIZE));
    return 0;
}
