#include "urp/host_context.h"
#include <stdint.h>
#include <stddef.h>

__attribute__((noinline, visibility("hidden")))
int32_t urp_transform_target(
    const urp_host_context_v1 *host,
    const urp_launch_args_v1 *args)
{
    /* The unwind test must cover a genuinely conditional, transformed frame.
     * AArch64 GCC -O2 lowers ordinary null guards into CBZ, outside the
     * currently supported NZCV b.cond flattening family. Force actual CMP +
     * B.EQ decisions in this fixture, using compiler-derived ABI offsets.
     * This does not claim support for CBZ in arbitrary user functions.
     */
    volatile uint32_t frame_anchor = 0;
    (void)frame_anchor;
    (void)args;

    __asm__ volatile goto (
        "cmp %x[host], #0\n\t"
        "b.eq %l[skip_diagnostic]\n\t"
        "ldr x16, [%x[host], #%c[callback_offset]]\n\t"
        "cmp x16, #0\n\t"
        "b.eq %l[skip_diagnostic]\n\t"
        :
        : [host] "r" (host),
          [callback_offset] "i" (offsetof(urp_host_context_v1, emit_diagnostic))
        : "cc", "x16", "memory"
        : skip_diagnostic);

    (void)host->emit_diagnostic(host->userdata, UINT32_C(0xCF10), 0);
skip_diagnostic:
    return 42;
}

extern __typeof__(urp_transform_target) urp_entry
    __attribute__((alias("urp_transform_target"), visibility("default")));
