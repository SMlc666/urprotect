.arch armv8-a
.text
.align 2
.global tlsld_entry
.type tlsld_entry, %function
tlsld_entry:
    adrp x0, :tlsldm:tls_ld_value
    add x0, x0, :tlsldm_lo12_nc:tls_ld_value
    bl __tls_get_addr
    add x0, x0, #:dtprel_hi12:tls_ld_value+4, lsl #12
    add x0, x0, #:dtprel_lo12_nc:tls_ld_value+4
    ldr w0, [x0]
    ret
.size tlsld_entry, .-tlsld_entry

.section .tdata,"awT",%progbits
.align 3
.word 0xaabbccdd
.global tls_ld_value
.hidden tls_ld_value
.type tls_ld_value, %object
tls_ld_value:
    .word 0x11223344
.size tls_ld_value, .-tls_ld_value

.section .tbss,"awT",%nobits
.align 3
.global tls_ld_zero
.hidden tls_ld_zero
.type tls_ld_zero, %object
tls_ld_zero:
    .zero 16
.size tls_ld_zero, .-tls_ld_zero

.extern __tls_get_addr
