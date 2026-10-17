.text
.align 2
.global urp_entry
.type urp_entry, %function
urp_entry:
    // Walk the complete bounded table in index order. Each case contributes its
    // exact signed result byte to a trace; only the full 0,1,2,3 trace returns 91.
    mov w0, #0
    mov w9, #0
.Ldispatch:
    cmp w0, #3
    bhi .Lverify
.ifdef URP_JUMP_TABLE_INDEX_CLOBBER
    // Nearest-negative fixture: ADRP writes X0 after CMP/B.HI, clobbering the
    // bounds-checked W0 index before the following indexed LDRSW.
    adrp x0, .Ltable
    add x0, x0, :lo12:.Ltable
    ldrsw x2, [x0, w0, uxtw #2]
.else
    adrp x1, .Ltable
    add x1, x1, :lo12:.Ltable
    ldrsw x2, [x1, w0, uxtw #2]
.endif
    adr x3, .Lcase0
    add x1, x3, x2
    br x1
.global urp_jump_table_case0
urp_jump_table_case0:
.Lcase0:
    mov w10, #17
    b .Lrecord_case
.global urp_jump_table_case1
urp_jump_table_case1:
.Lcase1:
    mov w10, #103
    b .Lrecord_case
.global urp_jump_table_case2
urp_jump_table_case2:
.Lcase2:
    mov w10, #-7
    b .Lrecord_case
.global urp_jump_table_case3
urp_jump_table_case3:
.Lcase3:
    mov w10, #91
    b .Lrecord_case
.Lrecord_case:
    and w10, w10, #0xff
    lsl w9, w9, #8
    orr w9, w9, w10
    add w0, w0, #1
    b .Ldispatch
.Lverify:
    // The four selected result bytes must be exactly 17, 103, -7, 91.
    movz w10, #0xf95b
    movk w10, #0x1167, lsl #16
    cmp w9, w10
    b.ne .Lfailed
    mov w0, #91
    ret
.Lfailed:
    mov w0, #-1
    ret
.size urp_entry, .-urp_entry

.align 2
.global urp_jump_table_outside_closure
.type urp_jump_table_outside_closure, %function
urp_jump_table_outside_closure:
    ret
.size urp_jump_table_outside_closure, .-urp_jump_table_outside_closure

.section .rodata
.align 2
.global urp_jump_table
urp_jump_table:
.Ltable:
    .word .Lcase0 - .Lcase0
    .word .Lcase1 - .Lcase0
    .word .Lcase2 - .Lcase0
    .word .Lcase3 - .Lcase0
