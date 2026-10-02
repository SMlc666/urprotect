.text
.global urp_transform_target
.type urp_transform_target, %function
.p2align 2
urp_transform_target:
    add x9, x0, x1
    eor x10, x9, x1
    add x0, x9, x10
    ret
.size urp_transform_target, .-urp_transform_target

.global urp_flatten_target
.type urp_flatten_target, %function
.p2align 2
urp_flatten_target:
    cmp x0, #0
    b.eq .Lflatten_zero
    mov x0, #7
    ret
.Lflatten_zero:
    mov x0, #3
    ret
.size urp_flatten_target, .-urp_flatten_target
