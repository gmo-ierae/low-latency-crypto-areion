# Copyright (c) 2025 GMO Cybersecurity by Ierae, Inc. All rights reserved.

    .arch   corei7
    .arch   .avx512f
    .arch   .avx512dq
    .arch   .avx512vl
    .arch   .vaes
    .arch   .ibt

    .text

    .set    state_field, 0
    .set    mask_field, 256
#
# global register allocation
#
# rdi m
# rsi out
# rdx in
# rcx inlen
#
# r8 alpha temp
# r9 input counter
#
# zmm28 RC[0...3]
# ...
# zmm31 RC[12..15]
#
    .set    zmm_RC, %zmm24
    .set    xmm_RC, %xmm24
    .set    zmm_s, %zmm25
    .set    ymm_s, %ymm25
    .set    xmm_s, %xmm25
    .set    zmm_t, %zmm26
    .set    ymm_t, %ymm26
    .set    xmm_t, %xmm26
    .set    zmm_zero, %zmm27
    .set    xmm_zero, %xmm27
    .set    zmm_RC0_3, %zmm28
    .set    zmm_RC4_7, %zmm29
    .set    zmm_RC8_11, %zmm30
    .set    zmm_RC12_15, %zmm31

    .p2align 4
load_global_regs:
    vpxorq  zmm_zero, zmm_zero, zmm_zero
    vmovdqa64 RC_0(%rip), zmm_RC0_3
    vmovdqa64 RC_4(%rip), zmm_RC4_7
    vmovdqa64 RC_8(%rip), zmm_RC8_11
    vmovdqa64 RC_12(%rip), zmm_RC12_15

    movq    $0xCC, %rax
    kmovw   %eax, %k1
    knotw   %k1, %k2
    ret

.macro  round   x0, x1, x2, x3, rc, zero, t
    vmovdqa64   \x0, \t
    vaesenc \x1, \x0, \x0
    vaesenclast	\rc, \x2, \x1
    vaesenc \zero, \x1, \x1
    vaesenc \x3, \x2, \x2
    vaesenclast	\zero, \t, \x3
.endm

.macro  inv_round   x0, x1, x2, x3, rc, zero, t
    vmovdqa64   \x2, \t
    vaesdeclast \rc, \x1, \x2
    vaesdeclast \zero, \x2, \x2
    vpxorq  \x3, \x0, \x1
    vaesdec \zero, \x3, \x0
    vaesenc \t, \x2, \x3
.endm

.macro  round_1_batch
    round   %xmm0, %xmm1, %xmm2, %xmm3, xmm_RC, xmm_zero, xmm_t
.endm

.macro  round_1_batch_zmm
    round   %zmm0, %zmm1, %zmm2, %zmm3, zmm_RC, zmm_zero, zmm_t
.endm

.macro  inv_round_1_batch
    inv_round   %xmm0, %xmm1, %xmm2, %xmm3, xmm_RC, xmm_zero, xmm_t
.endm

.macro  inv_round_1_batch_zmm
    inv_round   %zmm0, %zmm1, %zmm2, %zmm3, zmm_RC, zmm_zero, zmm_t
.endm

.macro  perm_512    round
    vshufi64x2  $0x00, zmm_RC0_3, zmm_RC0_3, zmm_RC
    \round
    vshufi64x2  $0x55, zmm_RC0_3, zmm_RC0_3, zmm_RC
    \round
    vshufi64x2  $0xAA, zmm_RC0_3, zmm_RC0_3, zmm_RC
    \round
    vshufi64x2  $0xFF, zmm_RC0_3, zmm_RC0_3, zmm_RC
    \round
    vshufi64x2  $0x00, zmm_RC4_7, zmm_RC4_7, zmm_RC
    \round
    vshufi64x2  $0x55, zmm_RC4_7, zmm_RC4_7, zmm_RC
    \round
    vshufi64x2  $0xAA, zmm_RC4_7, zmm_RC4_7, zmm_RC
    \round
    vshufi64x2  $0xFF, zmm_RC4_7, zmm_RC4_7, zmm_RC
    \round
    vshufi64x2  $0x00, zmm_RC8_11, zmm_RC8_11, zmm_RC
    \round
    vshufi64x2  $0x55, zmm_RC8_11, zmm_RC8_11, zmm_RC
    \round
    vshufi64x2  $0xAA, zmm_RC8_11, zmm_RC8_11, zmm_RC
    \round
    vshufi64x2  $0xFF, zmm_RC8_11, zmm_RC8_11, zmm_RC
    \round
    vshufi64x2  $0x00, zmm_RC12_15, zmm_RC12_15, zmm_RC
    \round
    vshufi64x2  $0x55, zmm_RC12_15, zmm_RC12_15, zmm_RC
    \round
    vshufi64x2  $0xAA, zmm_RC12_15, zmm_RC12_15, zmm_RC
    \round
.endm

.macro  inv_perm_512_prologue_xmm
    # x0 = MC^-1(x0)
    # x1 = MC^-1(x1)
    vaesimc %xmm0, %xmm0
    vaesimc %xmm1, %xmm1
.endm

.macro  inv_perm_512_epilogue_xmm
    # x0 = MC(x0)
    # x1 = MC(x1)
    vaesdeclast xmm_zero, %xmm0, %xmm0
    vaesenc xmm_zero, %xmm0, %xmm0
    vaesdeclast xmm_zero, %xmm1, %xmm1
    vaesenc xmm_zero, %xmm1, %xmm1
.endm

.macro  inv_perm_512_prologue_zmm
    # x0 = MC^-1(x0)
    # x1 = MC^-1(x1)
    vaesenclast zmm_zero, %zmm0, %zmm0
    vaesdec zmm_zero, %zmm0, %zmm0
    vaesenclast zmm_zero, %zmm1, %zmm1
    vaesdec zmm_zero, %zmm1, %zmm1
.endm

.macro  inv_perm_512_epilogue_zmm
    # x0 = MC(x0)
    # x1 = MC(x1)
    vaesdeclast zmm_zero, %zmm0, %zmm0
    vaesenc zmm_zero, %zmm0, %zmm0
    vaesdeclast zmm_zero, %zmm1, %zmm1
    vaesenc zmm_zero, %zmm1, %zmm1
.endm

.macro  inv_perm_512    round
    vshufi64x2  $0xAA, zmm_RC12_15, zmm_RC12_15, zmm_RC
    \round
    vshufi64x2  $0x55, zmm_RC12_15, zmm_RC12_15, zmm_RC
    \round
    vshufi64x2  $0x00, zmm_RC12_15, zmm_RC12_15, zmm_RC
    \round
    vshufi64x2  $0xFF, zmm_RC8_11, zmm_RC8_11, zmm_RC
    \round
    vshufi64x2  $0xAA, zmm_RC8_11, zmm_RC8_11, zmm_RC
    \round
    vshufi64x2  $0x55, zmm_RC8_11, zmm_RC8_11, zmm_RC
    \round
    vshufi64x2  $0x00, zmm_RC8_11, zmm_RC8_11, zmm_RC
    \round
    vshufi64x2  $0xFF, zmm_RC4_7, zmm_RC4_7, zmm_RC
    \round
    vshufi64x2  $0xAA, zmm_RC4_7, zmm_RC4_7, zmm_RC
    \round
    vshufi64x2  $0x55, zmm_RC4_7, zmm_RC4_7, zmm_RC
    \round
    vshufi64x2  $0x00, zmm_RC4_7, zmm_RC4_7, zmm_RC
    \round
    vshufi64x2  $0xFF, zmm_RC0_3, zmm_RC0_3, zmm_RC
    \round
    vshufi64x2  $0xAA, zmm_RC0_3, zmm_RC0_3, zmm_RC
    \round
    vshufi64x2  $0x55, zmm_RC0_3, zmm_RC0_3, zmm_RC
    \round
    vshufi64x2  $0x00, zmm_RC0_3, zmm_RC0_3, zmm_RC
    \round
.endm

    .p2align 4
perm_512_xmm:
    perm_512    round_1_batch
    ret

    .p2align 4
perm_512_zmm:
    perm_512    round_1_batch_zmm
    ret

    .p2align 4
inv_perm_512_xmm:
    inv_perm_512_prologue_xmm
    inv_perm_512    inv_round_1_batch
    inv_perm_512_epilogue_xmm
    ret

    .p2align 4
inv_perm_512_zmm:
    inv_perm_512_prologue_zmm
    inv_perm_512    inv_round_1_batch_zmm
    inv_perm_512_epilogue_zmm
    ret

#
# OUT
# zmm4: mask
# zmm5: alpha(mask)
#
    .p2align 4
alpha_mask_1:
    vmovdqu64	mask_field(%rdi), %zmm4
    movq    %xmm4, %rax
    vpextrq $1, %xmm4, %r8
    rolq    $29, %rax
    shlq    $9, %r8
    xorq    %r8, %rax
    movq    %rax, %xmm5
    valignq $1, %zmm4, %zmm5, %zmm5
    ret

#
# OUT
# zmm4: mask
# zmm5: alpha^1(mask)
# zmm6: alpha^2(mask)
# zmm7: alpha^3(mask)
# zmm8: alpha^4(mask)
#
    .p2align 4
alpha_mask_4:
    vmovdqu64	mask_field(%rdi), %zmm4
    vprolq  $29, %zmm4, %zmm7
    vpsllq  $9, %zmm4, %zmm8
    valignq $1, %zmm8, %zmm8, %zmm8
    vpxorq  %zmm7, %zmm8, %zmm8
    valignq $1, %zmm4, %zmm8, %zmm5
    valignq $2, %zmm4, %zmm8, %zmm6
    valignq $3, %zmm4, %zmm8, %zmm7
    valignq $4, %zmm4, %zmm8, %zmm8
    ret

#
# IN
# zmm0 = (x0[0], x1[0], x2[0], x3[0])
# zmm1 = (x0[1], x1[1], x2[1], x3[1])
# zmm2 = (x0[2], x1[2], x2[2], x3[2])
# zmm3 = (x0[3], x1[3], x2[3], x3[3])
# OUT
# zmm0 = (x0[0], x0[1], x0[2], x0[3])
# zmm1 = (x1[0], x1[1], x1[2], x1[3])
# zmm2 = (x2[0], x2[1], x2[2], x2[3])
# zmm3 = (x3[0], x3[1], x3[2], x3[3])
#
transpose_4:
    vmovdqa64   %zmm0, %zmm16
    vmovdqa64   %zmm1, %zmm17
    vpermq  $0x4E, %zmm17, %zmm0{%k1}
    vpermq  $0x4E, %zmm16, %zmm1{%k2}
    vmovdqa64   %zmm2, %zmm16
    vmovdqa64   %zmm3, %zmm17
    vpermq  $0x4E, %zmm17, %zmm2{%k1}
    vpermq  $0x4E, %zmm16, %zmm3{%k2}

    vmovdqa64   %zmm0, %zmm16
    vmovdqa64   %zmm1, %zmm17
    vshufi64x2  $0x44, %zmm2, %zmm16, %zmm0
    vshufi64x2  $0xEE, %zmm2, %zmm16, %zmm2
    vshufi64x2  $0x44, %zmm3, %zmm17, %zmm1
    vshufi64x2  $0xEE, %zmm3, %zmm17, %zmm3
    ret

    .p2align 4
opp_512_absorb_block_1:
    # IN
    vmovdqu64	0x00(%rdx), %zmm0

    # alpha
    call    alpha_mask_1

    # update M
    vmovdqa64	%zmm5, mask_field(%rdi)

    # IN ^ M
    vpxorq	%zmm4, %zmm0, %zmm0

    # PERM
    vextracti32x4   $1, %zmm0, %xmm1
    vextracti32x4   $2, %zmm0, %xmm2
    vextracti32x4   $3, %zmm0, %xmm3
    call perm_512_xmm
    vinserti32x4    $1, %xmm1, %zmm0, %zmm0
    vinserti32x4    $2, %xmm2, %zmm0, %zmm0
    vinserti32x4    $3, %xmm3, %zmm0, %zmm0

    # S ^ PERM ^ M
    vpternlogq  $0x96, state_field(%rdi), %zmm4, %zmm0

    # update S
    vmovdqa64	%zmm0, state_field(%rdi)
    ret

    .p2align 4
opp_512_absorb_block_4:
    # IN
    vmovdqu64	0x00(%rdx), %zmm0
    vmovdqu64	0x40(%rdx), %zmm1
    vmovdqu64	0x80(%rdx), %zmm2
    vmovdqu64	0xC0(%rdx), %zmm3

    # alpha
    call    alpha_mask_4

    # update M
    vmovdqa64	%zmm8, mask_field(%rdi)

    # IN ^ M
    vpxorq  %zmm4, %zmm0, %zmm0
    vpxorq  %zmm5, %zmm1, %zmm1
    vpxorq  %zmm6, %zmm2, %zmm2
    vpxorq  %zmm7, %zmm3, %zmm3

    # PERM
    call transpose_4
    call perm_512_zmm
    call transpose_4

    # S ^ PERM ^ M
    vpternlogq  $0x96, state_field+0x00(%rdi), %zmm4, %zmm0
    vpternlogq  $0x96, state_field+0x40(%rdi), %zmm5, %zmm1
    vpternlogq  $0x96, state_field+0x80(%rdi), %zmm6, %zmm2
    vpternlogq  $0x96, state_field+0xC0(%rdi), %zmm7, %zmm3

    # update S
    vmovdqa64	%zmm0, state_field+0x00(%rdi)
    vmovdqa64	%zmm1, state_field+0x40(%rdi)
    vmovdqa64	%zmm2, state_field+0x80(%rdi)
    vmovdqa64	%zmm3, state_field+0xC0(%rdi)
    ret

    .p2align 4
opp_512_encrypt_block_1:
    # IN
    vmovdqu64	0x00(%rdx), %zmm0

    # S ^ IN
    vpxorq	state_field(%rdi), %zmm0, %zmm3
    # update S
    vmovdqa64	%zmm3, state_field(%rdi)

    # alpha
    call    alpha_mask_1

    # update M
    vmovdqa64	%zmm5, mask_field(%rdi)

    # IN ^ M
    vpxorq	%zmm4, %zmm0, %zmm0

    # PERM
    vextracti32x4   $1, %zmm0, %xmm1
    vextracti32x4   $2, %zmm0, %xmm2
    vextracti32x4   $3, %zmm0, %xmm3
    call perm_512_xmm
    vinserti32x4    $1, %xmm1, %zmm0, %zmm0
    vinserti32x4    $2, %xmm2, %zmm0, %zmm0
    vinserti32x4    $3, %xmm3, %zmm0, %zmm0

    # PERM ^ M
    vpxorq	%zmm4, %zmm0, %zmm0

    # OUT
    vmovdqu64	%zmm0, 0x00(%rsi)
    ret

    .p2align 4
opp_512_encrypt_block_4:
    # IN
    vmovdqu64	0x00(%rdx), %zmm0
    vmovdqu64	0x40(%rdx), %zmm1
    vmovdqu64	0x80(%rdx), %zmm2
    vmovdqu64	0xC0(%rdx), %zmm3

    # S ^ IN
    vmovdqa64   %zmm2, %zmm4
    vmovdqa64   %zmm3, %zmm5
    vpternlogq  $0x96, state_field+0x00(%rdi), %zmm0, %zmm4
    vpternlogq  $0x96, state_field+0x40(%rdi), %zmm1, %zmm5
    # update S
    vmovdqa64	%zmm4, state_field+0x00(%rdi)
    vmovdqa64	%zmm5, state_field+0x40(%rdi)

    # alpha
    call    alpha_mask_4

    # update M
    vmovdqa64	%zmm8, mask_field(%rdi)

    # IN ^ M
    vpxorq  %zmm4, %zmm0, %zmm0
    vpxorq  %zmm5, %zmm1, %zmm1
    vpxorq  %zmm6, %zmm2, %zmm2
    vpxorq  %zmm7, %zmm3, %zmm3

    # PERM
    call transpose_4
    call perm_512_zmm
    call transpose_4

    # PERM ^ M
    vpxorq  %zmm4, %zmm0, %zmm0
    vpxorq  %zmm5, %zmm1, %zmm1
    vpxorq  %zmm6, %zmm2, %zmm2
    vpxorq  %zmm7, %zmm3, %zmm3

    # OUT
    vmovdqu64	%zmm0, 0x00(%rsi)
    vmovdqu64	%zmm1, 0x40(%rsi)
    vmovdqu64	%zmm2, 0x80(%rsi)
    vmovdqu64	%zmm3, 0xC0(%rsi)
    ret

    .p2align 4
opp_512_decrypt_block_1:
    # IN
    vmovdqu64	0x00(%rdx), %zmm0

    # alpha
    call    alpha_mask_1

    # update M
    vmovdqa64	%zmm5, mask_field(%rdi)

    # IN ^ M
    vpxorq	%zmm4, %zmm0, %zmm0

    # PERM
    vextracti32x4   $1, %zmm0, %xmm1
    vextracti32x4   $2, %zmm0, %xmm2
    vextracti32x4   $3, %zmm0, %xmm3
    call inv_perm_512_xmm
    vinserti32x4    $1, %xmm1, %zmm0, %zmm0
    vinserti32x4    $2, %xmm2, %zmm0, %zmm0
    vinserti32x4    $3, %xmm3, %zmm0, %zmm0

    # PERM ^ M
    vpxorq	%zmm4, %zmm0, %zmm0

    # OUT
    vmovdqu64	%zmm0, 0x00(%rsi)

    # S ^ OUT
    vpxorq	state_field(%rdi), %zmm0, %zmm0
    # update S
    vmovdqa64	%zmm0, state_field(%rdi)
    ret

    .p2align 4
opp_512_decrypt_block_4:
    # IN
    vmovdqu64	0x00(%rdx), %zmm0
    vmovdqu64	0x40(%rdx), %zmm1
    vmovdqu64	0x80(%rdx), %zmm2
    vmovdqu64	0xC0(%rdx), %zmm3

    # alpha
    call    alpha_mask_4
    # update M
    vmovdqa64	%zmm8, mask_field(%rdi)

    # IN ^ M
    vpxorq  %zmm4, %zmm0, %zmm0
    vpxorq  %zmm5, %zmm1, %zmm1
    vpxorq  %zmm6, %zmm2, %zmm2
    vpxorq  %zmm7, %zmm3, %zmm3

    # PERM
    call transpose_4
    call inv_perm_512_zmm
    call transpose_4

    # PERM ^ M
    vpxorq  %zmm4, %zmm0, %zmm0
    vpxorq  %zmm5, %zmm1, %zmm1
    vpxorq  %zmm6, %zmm2, %zmm2
    vpxorq  %zmm7, %zmm3, %zmm3

    # OUT
    vmovdqu64	%zmm0, 0x00(%rsi)
    vmovdqu64	%zmm1, 0x40(%rsi)
    vmovdqu64	%zmm2, 0x80(%rsi)
    vmovdqu64	%zmm3, 0xC0(%rsi)

    # S ^ OUT
    vmovdqa64   %zmm2, %zmm4
    vmovdqa64   %zmm3, %zmm5
    vpternlogq  $0x96, state_field+0x00(%rdi), %zmm0, %zmm4
    vpternlogq  $0x96, state_field+0x40(%rdi), %zmm1, %zmm5
    # update S
    vmovdqa64	%zmm4, state_field+0x00(%rdi)
    vmovdqa64	%zmm5, state_field+0x40(%rdi)
    ret

#
# size_t opp_512_absorb_data_asm(opp_memory_t *m, void *dummy, const unsigned char *in, size_t inlen)
#
# rdi = m
# rsi = dummy
# rdx = in
# rcx = inlen
#
    .p2align 4
    .globl	opp_512_absorb_data_asm
    .type	opp_512_absorb_data_asm, @function
opp_512_absorb_data_asm:
    .cfi_startproc
    endbr64

    call    load_global_regs

    xorq    %r9, %r9

    mov $0x100, %r10
    cmp %r10, %rcx
    jb  1f
2:
    call opp_512_absorb_block_4
    # add %r10, %rsi
    add %r10, %rdx
    sub %r10, %rcx
    add %r10, %r9
    cmp %r10, %rcx
    jae 2b
1:

    mov $0x40, %r10
    cmp %r10, %rcx
    jb  1f
2:
    call opp_512_absorb_block_1
    # add %r10, %rsi
    add %r10, %rdx
    sub %r10, %rcx
    add %r10, %r9
    cmp %r10, %rcx
    jae 2b
1:
    mov %r9, %rax
    ret
    .cfi_endproc
    .size	opp_512_absorb_data_asm, .-opp_512_absorb_data_asm

#
# size_t opp_512_encrypt_data_asm(opp_memory_t *m, unsigned char *out, const unsigned char *in, size_t inlen)
#
# rdi = m
# rsi = out
# rdx = in
# rcx = inlen
#
    .p2align 4
    .globl	opp_512_encrypt_data_asm
    .type	opp_512_encrypt_data_asm, @function
opp_512_encrypt_data_asm:
    .cfi_startproc
    endbr64

    call    load_global_regs

    xorq    %r9, %r9

    mov $0x100, %r10
    cmp %r10, %rcx
    jb  1f
2:
    call opp_512_encrypt_block_4
    add %r10, %rsi
    add %r10, %rdx
    sub %r10, %rcx
    add %r10, %r9
    cmp %r10, %rcx
    jae 2b
1:

    mov $0x40, %r10
    cmp %r10, %rcx
    jb  1f
2:
    call opp_512_encrypt_block_1
    add %r10, %rsi
    add %r10, %rdx
    sub %r10, %rcx
    add %r10, %r9
    cmp %r10, %rcx
    jae 2b
1:
    mov %r9, %rax
    ret
    .cfi_endproc
    .size	opp_512_encrypt_data_asm, .-opp_512_encrypt_data_asm


#
# size_t opp_512_decrypt_data_asm(opp_memory_t *m, unsigned char *out, const unsigned char *in, size_t inlen)
#
# rdi = m
# rsi = out
# rdx = in
# rcx = inlen
#
    .p2align 4
    .globl	opp_512_decrypt_data_asm
    .type	opp_512_decrypt_data_asm, @function
opp_512_decrypt_data_asm:
    .cfi_startproc
    endbr64

    call    load_global_regs

    xorq    %r9, %r9

    mov $0x100, %r10
    cmp %r10, %rcx
    jb  1f
2:
    call opp_512_decrypt_block_4
    add %r10, %rsi
    add %r10, %rdx
    sub %r10, %rcx
    add %r10, %r9
    cmp %r10, %rcx
    jae 2b
1:

    mov $0x40, %r10
    cmp %r10, %rcx
    jb  1f
2:
    call opp_512_decrypt_block_1
    add %r10, %rsi
    add %r10, %rdx
    sub %r10, %rcx
    add %r10, %r9
    cmp %r10, %rcx
    jae 2b
1:
    mov %r9, %rax
    ret
    .cfi_endproc
    .size	opp_512_decrypt_data_asm, .-opp_512_decrypt_data_asm

    .section	.rodata.cst16,"aM",@progbits,16
    .align 64
RC_0:
    .long   0x03707344
    .long   0x13198a2e
    .long   0x85a308d3
    .long   0x243f6a88
RC_1:
    .long   0xec4e6c89
    .long   0x082efa98
    .long   0x299f31d0
    .long   0xa4093822
RC_2:
    .long   0x34e90c6c
    .long   0xbe5466cf
    .long   0x38d01377
    .long   0x452821e6
RC_3:
    .long   0xb5470917
    .long   0x3f84d5b5
    .long   0xc97c50dd
    .long   0xc0ac29b7
RC_4:
    .long   0x98dfb5ac
    .long   0xd1310ba6
    .long   0x8979fb1b
    .long   0x9216d5d9
RC_5:
    .long   0x6a267e96
    .long   0xb8e1afed
    .long   0xd01adfb7
    .long   0x2ffd72db
RC_6:
    .long   0xb3916cf7
    .long   0x24a19947
    .long   0xf12c7f99
    .long   0xba7c9045
RC_7:
    .long   0x1574e690
    .long   0x36920d87
    .long   0x58efc166
    .long   0x801f2e28
RC_8:
    .long   0x728eb658
    .long   0x0d95748f
    .long   0xf4933d7e
    .long   0xa458fea3
RC_9:
    .long   0xc25a59b5
    .long   0x7b54a41d
    .long   0x82154aee
    .long   0x718bcd58
RC_10:
    .long   0x286085f0
    .long   0xc5d1b023
    .long   0x2af26013
    .long   0x9c30d539
RC_11:
    .long   0x603a180e
    .long   0x8e79dcb0
    .long   0xb8db38ef
    .long   0xca417918
RC_12:
    .long   0xbd314b27
    .long   0xd71577c1
    .long   0xb01e8a3e
    .long   0x6c9e0e8b
RC_13:
    .long   0xaa55ab94
    .long   0xe65525f3
    .long   0x55605c60
    .long   0x78af2fda
RC_14:
    .long   0x2aab10b6
    .long   0x55ca396a
    .long   0x63e81440
    .long   0x57489862
RC_15:
    .long   0
    .long   0
    .long   0
    .long   0

    .section	.note.GNU-stack,"",@progbits
