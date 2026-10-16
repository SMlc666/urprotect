.text
.p2align 2
.globl urp_entry
.type urp_entry, %function
urp_entry:
    stp x29, x30, [sp, #-16]!
    adrp x1, :got:getpid
    mov x2, x1
    mov x1, xzr
    mov x0, xzr
    ldr x9, [x2, :got_lo12:getpid]
    blr x9
    cmp w0, #0
    b.le .Lgetpid_failed
    mov w0, #97
    ldp x29, x30, [sp], #16
    ret
.Lgetpid_failed:
    mov w0, #96
    ldp x29, x30, [sp], #16
    ret
.size urp_entry, .-urp_entry
