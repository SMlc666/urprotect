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
    adrp x0, :tlsgd:tls_gd_value
    add x0, x0, :tlsgd_lo12:tls_gd_value
    bl __tls_get_addr
    ldr w0, [x0]
    ldp x29, x30, [sp], #16
    ret
.size urp_entry, .-urp_entry

.section .tdata,"awT",%progbits
.align 3
.global tls_gd_value
.type tls_gd_value, %object
tls_gd_value:
    .word 43
.size tls_gd_value, .-tls_gd_value
