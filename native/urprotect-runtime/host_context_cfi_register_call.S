.arch armv8-a
.text
.align 2
.global urp_cfi_invoke_with_registers
.type urp_cfi_invoke_with_registers, %function
urp_cfi_invoke_with_registers:
    stp x29, x30, [sp, #-64]!
    stp x19, x20, [sp, #16]
    .cfi_startproc
    .cfi_def_cfa_offset 64
    .cfi_offset 29, -64
    .cfi_offset 30, -56
    .cfi_offset 19, -48
    .cfi_offset 20, -40
    str x3, [sp, #32]
    str x4, [sp, #40]
    mov x29, sp
    mov x9, x0
    mov x10, x1
    mov x11, x2
    movz x19, #0x7788
    movk x19, #0x5566, lsl #16
    movk x19, #0x3344, lsl #32
    movk x19, #0x1122, lsl #48
    movz x20, #0x2211
    movk x20, #0x4433, lsl #16
    movk x20, #0x6655, lsl #32
    movk x20, #0x8877, lsl #48
    mov x0, x10
    mov x1, x11
    blr x9
    // This label names the instruction PC returned to by BLR, where the
    // caller's register-call FDE must be active while unwinding the throw.
    .global urp_cfi_invoke_with_registers_call_return
    .type urp_cfi_invoke_with_registers_call_return, %notype
urp_cfi_invoke_with_registers_call_return:
    mov x8, x0
    ldr x3, [sp, #32]
    ldr x4, [sp, #40]
    str x19, [x3]
    str x20, [x4]
    mov x0, x8
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #64
    .cfi_def_cfa_offset 0
    ret
    .cfi_endproc
.size urp_cfi_invoke_with_registers, .-urp_cfi_invoke_with_registers
