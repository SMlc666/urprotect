#include <stdint.h>
#include <stdio.h>

extern uint64_t urp_transform_target(uint64_t left, uint64_t right);
extern uint64_t urp_flatten_target(uint64_t value);

int main(void)
{
    const uint64_t normal = urp_transform_target(7, 4);
    const uint64_t zero = urp_transform_target(0, 4);
    const uint64_t branch = urp_flatten_target(1);
    const uint64_t branch_zero = urp_flatten_target(0);
    printf("urprotect-protection-fixture:%llu:%llu:%llu:%llu\n",
           (unsigned long long)normal,
           (unsigned long long)zero,
           (unsigned long long)branch,
           (unsigned long long)branch_zero);
    return normal == 26 && zero == 4 && branch == 7 && branch_zero == 3 ? 0 : 1;
}
