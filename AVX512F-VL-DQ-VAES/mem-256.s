# Copyright (c) 2025 GMO Cybersecurity by Ierae, Inc. All rights reserved.

    .arch   corei7
    .arch   .avx512f
    .arch   .avx512dq
    .arch   .avx512vl
    .arch   .vaes
    .arch   .ibt

    .text

    .set    state_field, 0
    .set    mask_field, 128

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
# zmm29 RC[0...3]
# zmm30 RC[4...7]
# zmm31 RC[8...11]
#

    .set    zmm_mask_permi2q_0, %zmm24
    .set    zmm_mask_permi2q_1, %zmm25
    .set    zmm_RC, %zmm26
    .set    xmm_RC, %xmm26
    .set    zmm_s, %zmm26
    .set    ymm_s, %ymm26
    .set    xmm_s, %xmm26
    .set    zmm_t, %zmm27
    .set    ymm_t, %ymm27
    .set    xmm_t, %xmm27
    .set    zmm_zero, %zmm28
    .set    xmm_zero, %xmm28
    .set    zmm_RC0_3, %zmm29
    .set    zmm_RC4_7, %zmm30
    .set    zmm_RC8_11, %zmm31

    .p2align 4
load_global_regs:
    vmovdqa64   mask_permi2q_0(%rip), zmm_mask_permi2q_0
    vmovdqa64   mask_permi2q_1(%rip), zmm_mask_permi2q_1
    vpxorq  zmm_zero, zmm_zero, zmm_zero
    vmovdqa64 RC_0(%rip), zmm_RC0_3
    vmovdqa64 RC_4(%rip), zmm_RC4_7
    vmovdqa64 RC_8(%rip), zmm_RC8_11

    movq    $0xCC, %rax
    kmovw   %eax, %k1
    knotw   %k1, %k2

    movq    $0x01, %rax
    kmovw   %eax, %k3
    movq    $0x02, %rax
    kmovw   %eax, %k4
    movq    $0x04, %rax
    kmovw   %eax, %k5
    movq    $0x08, %rax
    kmovw   %eax, %k6
    ret

#
# batch ROUND function
#
# IN
# ([xyz]mm0, [xyz]mm1): first input state
# ([xyz]mm2, [xyz]mm3): second input state
# ...
#
# OUT
# ([xyz]mm1, [xyz]mm0): first output state
# ([xyz]mm3, [xyz]mm2): second output state
# ...
#

.macro  round   x0, x1, rc, zero, t
    vaesenc	\rc, \x0, \t
    vaesenc	\x1, \t, \t
    vaesenclast	\zero, \x0, \x1
    vmovdqa64 \t, \x0
.endm

.macro  inv_round   x0, x1, rc, zero, t
    vmovdqa64 \x0, \t
    vaesdeclast \zero, \x1, \x0
    vaesenc \rc, \x0, \x1
    vaesenc \t, \x1, \x1
.endm

.macro  round_1_batch
    round   %xmm0, %xmm1, xmm_RC, xmm_zero, xmm_t
.endm

.macro  round_2_batch_zmm
    round   %zmm0, %zmm1, zmm_RC, zmm_zero, zmm_t
    round   %zmm2, %zmm3, zmm_RC, zmm_zero, zmm_t
.endm

.macro  round_1_batch_zmm
    round   %zmm0, %zmm1, zmm_RC, zmm_zero, zmm_t
.endm

.macro  inv_round_1_batch
    inv_round   %xmm0, %xmm1, xmm_RC, xmm_zero, xmm_t
.endm

.macro  inv_round_2_batch_zmm
    inv_round   %zmm0, %zmm1, zmm_RC, zmm_zero, zmm_t
    inv_round   %zmm2, %zmm3, zmm_RC, zmm_zero, zmm_t
.endm

.macro  inv_round_1_batch_zmm
    inv_round   %zmm0, %zmm1, zmm_RC, zmm_zero, zmm_t
.endm

.macro  perm_256    round
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
.endm

.macro  inv_perm_256    round
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
perm_256_xmm:
    perm_256    round_1_batch
    ret

    .p2align 4
perm_256_zmm:
    perm_256    round_1_batch_zmm
    ret

    .p2align 4
perm_256_zmm_2_batch:
    perm_256    round_2_batch_zmm
    ret

    .p2align 4
inv_perm_256_xmm:
    inv_perm_256    inv_round_1_batch
    ret

    .p2align 4
inv_perm_256_zmm:
    inv_perm_256    inv_round_1_batch_zmm
    ret

    .p2align 4
inv_perm_256_zmm_2_batch:
    inv_perm_256    inv_round_2_batch_zmm
    ret

#
# OUT
# ymm4: mask
# ymm5: alpha(mask)
#
    .p2align 4
alpha_mask_1:
    vmovdqu	mask_field(%rdi), %ymm4
    movq    %xmm4, %rax
    movq    mask_field+24(%rdi), %r8
    rolq	$3, %rax
    shrq	$5, %r8
    xorq	%r8, %rax
    movq    %rax, %xmm5
    valignq $1, %ymm4, %ymm5, %ymm5
    ret

.macro  alpha_4 ymm_src, ymm_dst
    vprolq  $3, \ymm_src, ymm_t

    vpextrq	$0, xmm_t, %rax
    shrq	$5, %r8
    xorq	%rax, %r8
    vpbroadcastq    %r8, \ymm_dst{%k3}

    vpextrq $1, xmm_t, %rax
    shrq	$5, %r8
    xorq	%rax, %r8
    vpbroadcastq    %r8, \ymm_dst{%k4}

    vextracti32x4   $1, ymm_t, xmm_t

    vpextrq	$0, xmm_t, %rax
    shrq	$5, %r8
    xorq	%rax, %r8
    vpbroadcastq    %r8, \ymm_dst{%k5}

    vpextrq $1, xmm_t, %rax
    shrq	$5, %r8
    xorq	%rax, %r8
    vpbroadcastq    %r8, \ymm_dst{%k6}
.endm

#
# OUT
# zmm8: (mask, alpha(mask))
# zmm9: (alpha^2(mask), alpha^3(mask))
# ymm10: alpha^4(mask)
#
    .p2align 4
alpha_mask_4:
    vmovdqu64 mask_field(%rdi), %ymm11
    movq    mask_field+24(%rdi), %r8

    alpha_4 %ymm11, %ymm10

    vmovdqa64   zmm_mask_permi2q_0, %zmm8
    vmovdqa64   zmm_mask_permi2q_1, %zmm9

    vpermi2q    %zmm10, %zmm11, %zmm8
    vpermi2q    %zmm10, %zmm11, %zmm9
    ret

#
# OUT
# zmm8: (mask, alpha(mask))
# zmm9: (alpha^2(mask), alpha^3(mask))
# zmm10: (alpha^4(mask), alpha^5(mask)
# zmm11: (alpha^6(mask), alpha^7(mask)
# ymm12: alpha^8(mask)
#
    .p2align 4
alpha_mask_8:
    vmovdqu64 mask_field(%rdi), %ymm14
    movq    mask_field+24(%rdi), %r8

    alpha_4 %ymm14, %ymm13
    alpha_4 %ymm13, %ymm12

    vmovdqa64   zmm_mask_permi2q_0, %zmm8
    vmovdqa64   zmm_mask_permi2q_1, %zmm9
    vmovdqa64   zmm_mask_permi2q_0, %zmm10
    vmovdqa64   zmm_mask_permi2q_1, %zmm11

    vpermi2q    %zmm13, %zmm14, %zmm8
    vpermi2q    %zmm13, %zmm14, %zmm9
    vpermi2q    %zmm12, %zmm13, %zmm10
    vpermi2q    %zmm12, %zmm13, %zmm11
    ret

#
# IN
# zmm0 = (x0[0], x1[0], x0[1], x1[1])
# zmm1 = (x0[2], x1[2], x0[3], x1[3])
# OUT
# zmm0 = (x0[0], x0[2], x0[1], x0[3])
# zmm1 = (x1[0], x1[2], x1[1], x1[3])
#
transpose_4:
    vmovdqa64   %zmm0, %zmm16
    vmovdqa64   %zmm1, %zmm17
    vpermq  $0x4E, %zmm17, %zmm0{%k1}
    vpermq  $0x4E, %zmm16, %zmm1{%k2}
    ret

#
# IN
# zmm0 = (x0[0], x1[0], x0[1], x1[1])
# zmm1 = (x0[2], x1[2], x0[3], x1[3])
# zmm2 = (x0[4], x1[4], x0[5], x1[5])
# zmm3 = (x0[6], x1[6], x0[7], x1[7])
# OUT
# zmm0 = (x0[0], x0[2], x0[1], x0[3])
# zmm1 = (x1[0], x1[2], x1[1], x1[3])
# zmm2 = (x0[4], x0[6], x0[5], x0[7])
# zmm3 = (x1[4], x1[6], x1[5], x1[7])
#
transpose_8:
    vmovdqa64   %zmm0, %zmm16
    vmovdqa64   %zmm1, %zmm17
    vpermq  $0x4E, %zmm17, %zmm0{%k1}
    vpermq  $0x4E, %zmm16, %zmm1{%k2}
    vmovdqa64   %zmm2, %zmm16
    vmovdqa64   %zmm3, %zmm17
    vpermq  $0x4E, %zmm17, %zmm2{%k1}
    vpermq  $0x4E, %zmm16, %zmm3{%k2}
    ret

    .p2align 4
opp_256_absorb_block_1:
    # IN
    vmovdqu	0x00(%rdx), %ymm0

    # alpha
    call    alpha_mask_1

    # update M
    vmovdqa	%ymm5, mask_field(%rdi)

    # IN ^ M
    vpxor	%ymm4, %ymm0, %ymm0

    # PERM
    vextracti32x4   $1, %ymm0, %xmm1
    call perm_256_xmm
    vinserti32x4    $1, %xmm1, %ymm0, %ymm0

    # S ^ PERM ^ M
    vpternlogq  $0x96, state_field+0x00(%rdi), %ymm4, %ymm0

    # update S
    vmovdqa	%ymm0, state_field(%rdi)
    ret

    .p2align 4
opp_256_absorb_block_4:
    # IN
    vmovdqu64   0x00(%rdx), %zmm0
    vmovdqu64   0x40(%rdx), %zmm1

    # alpha
    call    alpha_mask_4

    # update M
    vmovdqa	%ymm10, mask_field(%rdi)

    # IN ^ M
    vpxorq  %zmm8, %zmm0, %zmm0
    vpxorq  %zmm9, %zmm1, %zmm1

    # PERM
    call transpose_4
    call perm_256_zmm
    call transpose_4

    # S ^ PERM ^ M
    vpternlogq   $0x96, state_field+0x00(%rdi), %zmm8, %zmm0
    vpternlogq   $0x96, state_field+0x40(%rdi), %zmm9, %zmm1
    # update S
    vmovdqa64	%zmm0, state_field+0x00(%rdi)
    vmovdqa64	%zmm1, state_field+0x40(%rdi)
    ret

    .p2align 4
opp_256_absorb_block_8:
    # IN
    vmovdqu64   0x00(%rdx), %zmm0
    vmovdqu64   0x40(%rdx), %zmm1
    vmovdqu64   0x80(%rdx), %zmm2
    vmovdqu64   0xC0(%rdx), %zmm3

    # alpha
    call    alpha_mask_8

    # update M
    vmovdqa	%ymm12, mask_field(%rdi)

    # IN ^ M
    vpxorq  %zmm8, %zmm0, %zmm0
    vpxorq  %zmm9, %zmm1, %zmm1
    vpxorq  %zmm10, %zmm2, %zmm2
    vpxorq  %zmm11, %zmm3, %zmm3

    # PERM
    call transpose_8
    call perm_256_zmm_2_batch
    call transpose_8

    # PERM ^ M
    vpxorq  %zmm8, %zmm0, %zmm0
    vpxorq  %zmm9, %zmm1, %zmm1
    vpxorq  %zmm10, %zmm2, %zmm2
    vpxorq  %zmm11, %zmm3, %zmm3

    # S ^ PERM ^ M
    vmovdqa64   %zmm0, %zmm14
    vmovdqa64   %zmm1, %zmm15
    vpternlogq  $0x96, state_field+0x00(%rdi), %zmm2, %zmm14
    vpternlogq  $0x96, state_field+0x40(%rdi), %zmm3, %zmm15

    # update S
    vmovdqa64	%zmm14, state_field+0x00(%rdi)
    vmovdqa64	%zmm15, state_field+0x40(%rdi)
    ret

    .p2align 4
opp_256_encrypt_block_1:
    # IN
    vmovdqu	0x00(%rdx), %ymm0

    # S ^ IN
    vpxor	state_field(%rdi), %ymm0, %ymm3
    # update S
    vmovdqa	%ymm3, state_field(%rdi)

    # alpha
    call    alpha_mask_1

    # update M
    vmovdqa	%ymm5, mask_field(%rdi)

    # IN ^ M
    vpxor	%ymm4, %ymm0, %ymm0

    # PERM
    vextracti32x4   $1, %ymm0, %xmm1
    call perm_256_xmm
    vinserti32x4    $1, %xmm1, %ymm0, %ymm0

    # PERM ^ M
    vpxor	%ymm4, %ymm0, %ymm0

    # OUT
    vmovdqu	%ymm0, 0x00(%rsi)
    ret

    .p2align 4
opp_256_encrypt_block_4:
    # IN
    vmovdqu64   0x00(%rdx), %zmm0
    vmovdqu64   0x40(%rdx), %zmm1

    # S ^ IN
    vpxorq   state_field+0x00(%rdi), %zmm0, %zmm2
    vpxorq   state_field+0x40(%rdi), %zmm1, %zmm3
    # update S
    vmovdqa64	%zmm2, state_field+0x00(%rdi)
    vmovdqa64	%zmm3, state_field+0x40(%rdi)

    # alpha
    call    alpha_mask_4

    # update M
    vmovdqa	%ymm10, mask_field(%rdi)

    # IN ^ M
    vpxorq  %zmm8, %zmm0, %zmm0
    vpxorq  %zmm9, %zmm1, %zmm1

    # PERM
    call transpose_4
    call perm_256_zmm
    call transpose_4

    # PERM ^ M
    vpxorq  %zmm8, %zmm0, %zmm0
    vpxorq  %zmm9, %zmm1, %zmm1

    # OUT
    vmovdqu64   %zmm0, (%rsi)
    vmovdqu64   %zmm1, 64(%rsi)
    ret

    .p2align 4
opp_256_encrypt_block_8:
    # IN
    vmovdqu64   0x00(%rdx), %zmm0
    vmovdqu64   0x40(%rdx), %zmm1
    vmovdqu64   0x80(%rdx), %zmm2
    vmovdqu64   0xC0(%rdx), %zmm3

    # S ^ IN
    vmovdqa64   %zmm0, %zmm14
    vmovdqa64   %zmm1, %zmm15
    vpternlogq  $0x96, state_field+0x00(%rdi), %zmm2, %zmm14
    vpternlogq  $0x96, state_field+0x40(%rdi), %zmm3, %zmm15

    # update S
    vmovdqa64	%zmm14, state_field+0x00(%rdi)
    vmovdqa64	%zmm15, state_field+0x40(%rdi)

    # alpha
    call    alpha_mask_8

    # update M
    vmovdqa	%ymm12, mask_field(%rdi)

    # IN ^ M
    vpxorq  %zmm8, %zmm0, %zmm0
    vpxorq  %zmm9, %zmm1, %zmm1
    vpxorq  %zmm10, %zmm2, %zmm2
    vpxorq  %zmm11, %zmm3, %zmm3

    # PERM
    call transpose_8
    call perm_256_zmm_2_batch
    call transpose_8

    # PERM ^ M
    vpxorq  %zmm8, %zmm0, %zmm0
    vpxorq  %zmm9, %zmm1, %zmm1
    vpxorq  %zmm10, %zmm2, %zmm2
    vpxorq  %zmm11, %zmm3, %zmm3

    # OUT
    vmovdqu64   %zmm0, 0x00(%rsi)
    vmovdqu64   %zmm1, 0x40(%rsi)
    vmovdqu64   %zmm2, 0x80(%rsi)
    vmovdqu64   %zmm3, 0xC0(%rsi)
    ret

    .p2align 4
opp_256_decrypt_block_1:
    # IN
    vmovdqu	0x00(%rdx), %ymm0

    # alpha
    call    alpha_mask_1

    # update M
    vmovdqa	%ymm5, mask_field(%rdi)

    # IN ^ M
    vpxor	%ymm4, %ymm0, %ymm0

    # PERM
    vextracti32x4   $1, %ymm0, %xmm1
    call inv_perm_256_xmm
    vinserti32x4    $1, %xmm1, %ymm0, %ymm0

    # PERM ^ M
    vpxor	%ymm4, %ymm0, %ymm0

    # OUT
    vmovdqu	%ymm0, 0x00(%rsi)

    # S ^ OUT
    vpxor	state_field(%rdi), %ymm0, %ymm0
    vmovdqa	%ymm0, state_field(%rdi)
    ret

    .p2align 4
opp_256_decrypt_block_4:
    # IN
    vmovdqu64   0x00(%rdx), %zmm0
    vmovdqu64   0x40(%rdx), %zmm1

    # alpha
    call    alpha_mask_4

    # update M
    vmovdqa	%ymm10, mask_field(%rdi)

    # IN ^ M
    vpxorq  %zmm8, %zmm0, %zmm0
    vpxorq  %zmm9, %zmm1, %zmm1

    # PERM
    call transpose_4
    call inv_perm_256_zmm
    call transpose_4

    # PERM ^ M
    vpxorq  %zmm8, %zmm0, %zmm0
    vpxorq  %zmm9, %zmm1, %zmm1

    # OUT
    vmovdqu64   %zmm0, (%rsi)
    vmovdqu64   %zmm1, 64(%rsi)

    # S ^ OUT
    vpxorq   state_field+0x00(%rdi), %zmm0, %zmm2
    vpxorq   state_field+0x40(%rdi), %zmm1, %zmm3
    # update S
    vmovdqa64	%zmm2, state_field+0x00(%rdi)
    vmovdqa64	%zmm3, state_field+0x40(%rdi)
    ret

    .p2align 4
opp_256_decrypt_block_8:
    # IN
    vmovdqu64   0x00(%rdx), %zmm0
    vmovdqu64   0x40(%rdx), %zmm1
    vmovdqu64   0x80(%rdx), %zmm2
    vmovdqu64   0xC0(%rdx), %zmm3

    # alpha
    call    alpha_mask_8

    # update M
    vmovdqa	%ymm12, mask_field(%rdi)

    # IN ^ M
    vpxorq  %zmm8, %zmm0, %zmm0
    vpxorq  %zmm9, %zmm1, %zmm1
    vpxorq  %zmm10, %zmm2, %zmm2
    vpxorq  %zmm11, %zmm3, %zmm3

    # PERM
    call transpose_8
    call inv_perm_256_zmm_2_batch
    call transpose_8

    # PERM ^ M
    vpxorq  %zmm8, %zmm0, %zmm0
    vpxorq  %zmm9, %zmm1, %zmm1
    vpxorq  %zmm10, %zmm2, %zmm2
    vpxorq  %zmm11, %zmm3, %zmm3

    # OUT
    vmovdqu64   %zmm0, 0x00(%rsi)
    vmovdqu64   %zmm1, 0x40(%rsi)
    vmovdqu64   %zmm2, 0x80(%rsi)
    vmovdqu64   %zmm3, 0xC0(%rsi)

    # S ^ OUT
    vmovdqa64   %zmm0, %zmm14
    vmovdqa64   %zmm1, %zmm15
    vpternlogq  $0x96, state_field+0x00(%rdi), %zmm2, %zmm14
    vpternlogq  $0x96, state_field+0x40(%rdi), %zmm3, %zmm15

    # update S
    vmovdqa64	%zmm14, state_field+0x00(%rdi)
    vmovdqa64	%zmm15, state_field+0x40(%rdi)
    ret

#
# size_t opp_256_absorb_data_asm(opp_memory_t *m, void *dummy, const unsigned char *in, size_t inlen)
#
# rdi = m
# rsi = dummy
# rdx = in
# rcx = inlen
    .p2align 4
    .globl	opp_256_absorb_data_asm
    .type	opp_256_absorb_data_asm, @function
opp_256_absorb_data_asm:
    .cfi_startproc
    endbr64

    call    load_global_regs

    xor %r9, %r9

    mov $0x100, %r10
    cmp %r10, %rcx
    jb  1f
2:
    call opp_256_absorb_block_8
    # add %r10, %rsi
    add %r10, %rdx
    sub %r10, %rcx
    add %r10, %r9
    cmp %r10, %rcx
    jae 2b
1:

    mov $0x80, %r10
    cmp %r10, %rcx
    jb  1f
2:
    call opp_256_absorb_block_4
    # add %r10, %rsi
    add %r10, %rdx
    sub %r10, %rcx
    add %r10, %r9
    cmp %r10, %rcx
    jae 2b
1:

    mov $0x20, %r10
    cmp %r10, %rcx
    jb  1f
2:
    call opp_256_absorb_block_1
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
    .size	opp_256_absorb_data_asm, .-opp_256_absorb_data_asm

#
# size_t opp_256_encrypt_data_asm(opp_memory_t *m, unsigned char *out, const unsigned char *in, size_t inlen)
#
# rdi = m
# rsi = out
# rdx = in
# rcx = inlen
#
    .p2align 4
    .globl	opp_256_encrypt_data_asm
    .type	opp_256_encrypt_data_asm, @function
opp_256_encrypt_data_asm:
    .cfi_startproc
    endbr64

    call    load_global_regs

    xor %r9, %r9

    mov $0x100, %r10
    cmp %r10, %rcx
    jb  1f
2:
    call opp_256_encrypt_block_8
    add %r10, %rsi
    add %r10, %rdx
    sub %r10, %rcx
    add %r10, %r9
    cmp %r10, %rcx
    jae 2b
1:

    mov $0x80, %r10
    cmp %r10, %rcx
    jb  1f
2:
    call opp_256_encrypt_block_4
    add %r10, %rsi
    add %r10, %rdx
    sub %r10, %rcx
    add %r10, %r9
    cmp %r10, %rcx
    jae 2b
1:

    mov $0x20, %r10
    cmp %r10, %rcx
    jb  1f
2:
    call opp_256_encrypt_block_1
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
    .size	opp_256_encrypt_data_asm, .-opp_256_encrypt_data_asm


#
# size_t opp_256_decrypt_data_asm(opp_memory_t *m, unsigned char *out, const unsigned char *in, size_t inlen)
#
# rdi = m
# rsi = out
# rdx = in
# rcx = inlen
#
    .p2align 4
    .globl	opp_256_decrypt_data_asm
    .type	opp_256_decrypt_data_asm, @function
opp_256_decrypt_data_asm:
    .cfi_startproc
    endbr64

    call    load_global_regs

    xor %r9, %r9

    mov $0x100, %r10
    cmp %r10, %rcx
    jb  1f
2:
    call opp_256_decrypt_block_8
    add %r10, %rsi
    add %r10, %rdx
    sub %r10, %rcx
    add %r10, %r9
    cmp %r10, %rcx
    jae 2b
1:

    mov $0x80, %r10
    cmp %r10, %rcx
    jb  1f
2:
    call opp_256_decrypt_block_4
    add %r10, %rsi
    add %r10, %rdx
    sub %r10, %rcx
    add %r10, %r9
    cmp %r10, %rcx
    jae 2b
1:

    mov $0x20, %r10
    cmp %r10, %rcx
    jb  1f
2:
    call opp_256_decrypt_block_1
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
    .size	opp_256_decrypt_data_asm, .-opp_256_decrypt_data_asm

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
    .long   0
    .long   0
    .long   0
    .long   0
RC_11:
    .long   0
    .long   0
    .long   0
    .long   0

    .align 64
mask_permi2q_0:
    .quad   0
    .quad   1
    .quad   2
    .quad   3
    .quad   1
    .quad   2
    .quad   3
    .quad   8
mask_permi2q_1:
    .quad   2
    .quad   3
    .quad   8
    .quad   9
    .quad   3
    .quad   8
    .quad   9
    .quad   10


    .section	.note.GNU-stack,"",@progbits
