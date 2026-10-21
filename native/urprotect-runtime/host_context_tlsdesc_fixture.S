.arch armv8-a
.text
.align 2
.global urp_entry
.type urp_entry, %function
urp_entry:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    adrp x0, :tlsdesc:tls_desc_value
    ldr x1, [x0, #:tlsdesc_lo12:tls_desc_value]
    add x0, x0, :tlsdesc_lo12:tls_desc_value
    .tlsdesccall tls_desc_value
    blr x1
    mrs x1, tpidr_el0
    add x0, x1, x0
    ldr w0, [x0]
    ldp x29, x30, [sp], #16
    ret
.size urp_entry, .-urp_entry

.section .tdata,"awT",%progbits
.align 3
.global tls_desc_value
.type tls_desc_value, %tls_object
tls_desc_value:
    .word 43
.size tls_desc_value, .-tls_desc_value
