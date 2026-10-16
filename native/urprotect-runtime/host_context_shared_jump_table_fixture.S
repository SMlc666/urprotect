.text
.align 2
.global urp_entry
.type urp_entry, %function
urp_entry:
    // Selected consumer: force one ordered read/dispatch for every table index.
    mov w0, #0
    mov w9, #0
.Ldispatch:
    cmp w0, #3
    bhi .Lverify
    adrp x1, urp_shared_jump_table
    add x1, x1, :lo12:urp_shared_jump_table
    ldrsw x2, [x1, w0, uxtw #2]
    adr x3, .Lcase0
    add x1, x3, x2
    br x1
.global urp_shared_jump_table_case0
urp_shared_jump_table_case0:
.Lcase0:
    mov w10, #17
    b .Lrecord_case
.global urp_shared_jump_table_case1
urp_shared_jump_table_case1:
.Lcase1:
    mov w10, #103
    b .Lrecord_case
.global urp_shared_jump_table_case2
urp_shared_jump_table_case2:
.Lcase2:
    mov w10, #-7
    b .Lrecord_case
.global urp_shared_jump_table_case3
urp_shared_jump_table_case3:
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
.global urp_observer
.type urp_observer, %function
urp_observer:
    // The unselected consumer shares the table but starts at case zero. Its BR
    // enters the source case block, which completes the same ordered walk and
    // returns to the observer's caller through the original function epilogue.
    mov w0, #0
    mov w9, #0
    adrp x1, urp_shared_jump_table
    add x1, x1, :lo12:urp_shared_jump_table
    ldrsw x2, [x1, w0, uxtw #2]
    adr x3, .Lcase0
    add x1, x3, x2
    br x1
.size urp_observer, .-urp_observer

.section .rodata
.align 2
.global urp_shared_jump_table
.hidden urp_shared_jump_table
.type urp_shared_jump_table, %object
urp_shared_jump_table:
    .word .Lcase0 - .Lcase0
    .word .Lcase1 - .Lcase0
    .word .Lcase2 - .Lcase0
    .word .Lcase3 - .Lcase0
.size urp_shared_jump_table, .-urp_shared_jump_table
