.arch armv8-a
.text
.align 2
.global urp_entry
.type urp_entry, %function
urp_entry:
    mrs x0, tpidr_el0
    add x0, x0, #:tprel_hi12:tls_le_value, lsl #12
    add x0, x0, #:tprel_lo12_nc:tls_le_value
    ldr w0, [x0]
    ret
.size urp_entry, .-urp_entry

.section .tdata,"awT",%progbits
.align 3
.global tls_le_value
.type tls_le_value, %object
tls_le_value:
    .word 43
.size tls_le_value, .-tls_le_value
