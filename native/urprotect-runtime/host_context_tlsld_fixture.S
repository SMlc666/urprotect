.arch armv8-a
.text
.align 2
.global urp_entry
.type urp_entry, %function
.extern __tls_get_addr
.type __tls_get_addr, %function
urp_entry:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    adrp x0, :tlsldm:tls_ld_value
    add x0, x0, :tlsldm_lo12_nc:tls_ld_value
    bl __tls_get_addr
    add x0, x0, #:dtprel_hi12:tls_ld_value, lsl #12
    add x0, x0, #:dtprel_lo12:tls_ld_value
    ldr w0, [x0]
    ldp x29, x30, [sp], #16
    ret
.size urp_entry, .-urp_entry

.section .tdata,"awT",%progbits
.align 3
.word 0xaabbccdd
.type tls_ld_value, %tls_object
tls_ld_value:
    .word 43
.size tls_ld_value, .-tls_ld_value

.section .tbss,"awT",%nobits
.align 3
.type tls_ld_zero, %tls_object
tls_ld_zero:
    .zero 16
.size tls_ld_zero, .-tls_ld_zero
