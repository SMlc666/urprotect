#include "urp/host_context.h"
#include <stddef.h>
#include <stdint.h>

/*
 * CFI/unwind fixture for the *narrow, proven* HostContext callback ABI.
 * It intentionally uses CMP + B.EQ and the exact BLR X3 producer chain that
 * the native control-flow analyzer validates. This does NOT certify CBZ,
 * arbitrary BLR, or interprocedural transformations.
 *
 * This is real AArch64 code and carries a real .eh_frame FDE. A normal GCC
 * -O2 build of a C null check creates CBZ, an unsupported instruction in
 * the initial flattening pass. The explicit assembly keeps the fixture's
 * claim matched to the implemented instruction subset.
 */
_Static_assert(
    offsetof(urp_host_context_v1, userdata) == 16U,
    "HostContext CFI fixture requires the audited userdata ABI offset");
_Static_assert(
    offsetof(urp_host_context_v1, emit_diagnostic) == 48U,
    "HostContext CFI fixture requires the audited callback ABI offset");

__asm__(
    ".text\n"
    ".p2align 2\n"
    ".globl urp_transform_target\n"
    ".hidden urp_transform_target\n"
    ".type urp_transform_target, %function\n"
    "urp_transform_target:\n"
    ".cfi_startproc\n"
    "stp x29, x30, [sp, #-32]!\n"
    ".cfi_def_cfa_offset 32\n"
    ".cfi_offset x29, -32\n"
    ".cfi_offset x30, -24\n"
    "mov x29, sp\n"
    "str wzr, [sp, #28]\n"
    "ldr w1, [sp, #28]\n"
    "cmp x0, #0\n"
    "b.eq 1f\n"
    "ldr x3, [x0, #48]\n"
    "cmp x3, #0\n"
    "b.eq 1f\n"
    "ldr x0, [x0, #16]\n"
    "mov w1, #0xcf10\n"
    "mov x2, xzr\n"
    "blr x3\n"
    "1:\n"
    "mov w0, #42\n"
    "ldp x29, x30, [sp], #32\n"
    ".cfi_def_cfa sp, 0\n"
    "ret\n"
    ".cfi_endproc\n"
    ".size urp_transform_target, .-urp_transform_target\n"
    ".globl urp_entry\n"
    ".type urp_entry, %function\n"
    ".set urp_entry, urp_transform_target\n");
