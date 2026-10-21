.text
.align 2

.macro URP_EXTERNAL_DISPATCH symbol
.global \symbol
.type \symbol, %function
\symbol:
    // The test passes the desired bounded index in launch_args.argc.
    ldr w0, [x1, #8]
    cmp w0, #3
    bhi .Ldefault_\symbol
    adrp x9, :got:urp_external_jump_table
    ldr x9, [x9, :got_lo12:urp_external_jump_table]
    ldrsw x2, [x9, w0, uxtw #2]
    add x1, x9, x2
    br x1
.Ldefault_\symbol:
    mov w0, #-1
    ret
.size \symbol, .-\symbol
.endm

URP_EXTERNAL_DISPATCH urp_entry
URP_EXTERNAL_DISPATCH urp_observer

.extern urp_external_jump_table
.type urp_external_jump_table, %object
.size urp_external_jump_table, 16
