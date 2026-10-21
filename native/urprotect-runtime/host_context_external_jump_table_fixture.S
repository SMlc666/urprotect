.text
.align 2
.global urp_entry
.type urp_entry, %function
urp_entry:
    // Bounds-checked dispatch whose table pointer is loader-supplied through
    // an exact GOT slot for an undefined dynamic OBJECT symbol.
    cmp w0, #3
    bhi .Ldefault
    adrp x9, :got:urp_external_jump_table
    ldr x9, [x9, :got_lo12:urp_external_jump_table]
    ldrsw x2, [x9, w0, uxtw #2]
    adr x3, .Lcase0
    add x1, x3, x2
    br x1
.global urp_external_jump_table_case0
urp_external_jump_table_case0:
.Lcase0:
    mov w0, #17
    ret
.global urp_external_jump_table_case1
urp_external_jump_table_case1:
.Lcase1:
    mov w0, #103
    ret
.global urp_external_jump_table_case2
urp_external_jump_table_case2:
.Lcase2:
    mov w0, #-7
    ret
.global urp_external_jump_table_case3
urp_external_jump_table_case3:
.Lcase3:
    mov w0, #91
    ret
.Ldefault:
    mov w0, #-1
    ret
.size urp_entry, .-urp_entry

.extern urp_external_jump_table
.type urp_external_jump_table, %object
.size urp_external_jump_table, 16
