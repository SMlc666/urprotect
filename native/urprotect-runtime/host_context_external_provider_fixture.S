.text
.align 2
.global urp_provider_target_0
.protected urp_provider_target_0
.type urp_provider_target_0, %function
urp_provider_target_0:
.ifdef URP_PROVIDER_VARIANT
    mov w0, #18
.else
    mov w0, #17
.endif
    ret
.size urp_provider_target_0, .-urp_provider_target_0

.global urp_provider_target_1
.protected urp_provider_target_1
.type urp_provider_target_1, %function
urp_provider_target_1:
    mov w0, #103
    ret
.size urp_provider_target_1, .-urp_provider_target_1

.global urp_provider_target_2
.protected urp_provider_target_2
.type urp_provider_target_2, %function
urp_provider_target_2:
    mov w0, #-7
    ret
.size urp_provider_target_2, .-urp_provider_target_2

.global urp_provider_target_3
.protected urp_provider_target_3
.type urp_provider_target_3, %function
urp_provider_target_3:
    mov w0, #91
    ret
.size urp_provider_target_3, .-urp_provider_target_3

.section .rodata
.align 2
.global urp_external_jump_table
.type urp_external_jump_table, %object
urp_external_jump_table:
    .word urp_provider_target_0 - urp_external_jump_table
    .word urp_provider_target_1 - urp_external_jump_table
    .word urp_provider_target_2 - urp_external_jump_table
    .word urp_provider_target_3 - urp_external_jump_table
.ifdef URP_PROVIDER_BAD_SIZE
.size urp_external_jump_table, 12
.else
.size urp_external_jump_table, 16
.endif
