.text
.align 2
.global urp_entry
.type urp_entry, %function
urp_entry:
    // HostContext arguments are ignored; dispatch value 3 reaches case3.
    mov w0, #3
    cmp w0, #3
    bhi .Ldefault
    adrp x1, .Ltable
    add x1, x1, :lo12:.Ltable
    ldrsw x2, [x1, w0, uxtw #2]
    adr x3, .Lcase0
    add x1, x3, x2
    br x1
.Lcase0:
    mov w0, #17
    ret
.Lcase1:
    mov w0, #103
    ret
.Lcase2:
    mov w0, #-7
    ret
.Lcase3:
    mov w0, #91
    ret
.Ldefault:
    mov w0, #-1
    ret
.size urp_entry, .-urp_entry

.section .rodata
.align 2
.Ltable:
    .word .Lcase0 - .Lcase0
    .word .Lcase1 - .Lcase0
    .word .Lcase2 - .Lcase0
    .word .Lcase3 - .Lcase0
