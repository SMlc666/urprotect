.arch armv8-a
.text
.align 2
.global tlsdesc_entry
.type tlsdesc_entry, %function
tlsdesc_entry:
    adrp x0, :tlsdesc:tls_desc_value
    ldr x1, [x0, #:tlsdesc_lo12:tls_desc_value]
    add x0, x0, :tlsdesc_lo12:tls_desc_value
    .tlsdesccall tls_desc_value
    blr x1
    mrs x1, tpidr_el0
    add x0, x1, x0
    ldr w0, [x0]
    ret
.size tlsdesc_entry, .-tlsdesc_entry

.section .tdata,"awT",%progbits
.align 2
.global tls_desc_value
.type tls_desc_value, %object
tls_desc_value:
    .word 0x11223344
.size tls_desc_value, .-tls_desc_value

.section .tbss,"awT",%nobits
.align 3
.global tls_desc_zero
.type tls_desc_zero, %object
tls_desc_zero:
    .zero 16
.size tls_desc_zero, .-tls_desc_zero
