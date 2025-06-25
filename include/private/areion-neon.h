/* Copyright (c) 2025 GMO Cybersecurity by Ierae, Inc. All rights reserved. */

#ifndef AREION_NEON_H
#define AREION_NEON_H

#include <arm_neon.h>
#include "areion-const.h"

/*
static inline void print_word(const char *msg, areion_word_t x)
{
    printf("%s %08X %08X %08X %08X\n", msg,
        vgetq_lane_u32(vreinterpretq_u32_u8(x), 0),
        vgetq_lane_u32(vreinterpretq_u32_u8(x), 1),
        vgetq_lane_u32(vreinterpretq_u32_u8(x), 2),
        vgetq_lane_u32(vreinterpretq_u32_u8(x), 3)
    );
}
*/

static inline void areion_load_256(areion_word_t dst[2], const uint8_t src[32])
{
    dst[0] = vld1q_u8(&src[0]);
    dst[1] = vld1q_u8(&src[16]);
}

static inline void areion_store_256(uint8_t dst[32], const areion_word_t src[2])
{
    vst1q_u8(&dst[0], src[0]);
    vst1q_u8(&dst[16], src[1]);
}

static inline void areion_load_512(areion_word_t dst[4], const uint8_t src[64])
{
    dst[0] = vld1q_u8(&src[0]);
    dst[1] = vld1q_u8(&src[16]);
    dst[2] = vld1q_u8(&src[32]);
    dst[3] = vld1q_u8(&src[48]);
}

static inline void areion_store_512(uint8_t dst[64], const areion_word_t src[4])
{
    vst1q_u8(&dst[0],  src[0]);
    vst1q_u8(&dst[16], src[1]);
    vst1q_u8(&dst[32], src[2]);
    vst1q_u8(&dst[48], src[3]);
}

static inline areion_word_t areion_xor(areion_word_t x, areion_word_t y)
{
    return veorq_u8(x, y);
}

static inline uint64_t areion_extract0_64(areion_word_t x)
{
    return vgetq_lane_u64(vreinterpretq_u64_u8(x), 0);
}

static inline uint64_t areion_extract1_64(areion_word_t x)
{
    return vgetq_lane_u64(vreinterpretq_u64_u8(x), 1);
}

static inline areion_word_t round_constant_0(int i)
{
    return vmovq_n_u8(0);
}

static inline areion_word_t round_constant_1(int i)
{
    uint32_t x[] = {
        RC[4 * i + 3],
        RC[4 * i + 2],
        RC[4 * i + 1],
        RC[4 * i + 0],
    };
    return vreinterpretq_u8_u32(vld1q_u32(x));
}

static inline areion_word_t areion_A1(areion_word_t x, areion_word_t k)
{
    return vaesmcq_u8(vaeseq_u8(x, k));
}

static inline areion_word_t areion_A2(areion_word_t x, areion_word_t k)
{
    return vaeseq_u8(x, k);
}

static inline areion_word_t areion_A3(areion_word_t x)
{
    return vaesmcq_u8(x);
}

static inline areion_word_t areion_A4(areion_word_t x, areion_word_t k)
{
    return vaesdq_u8(x, k);
}

static inline areion_word_t areion_A5(areion_word_t x)
{
    return vaesimcq_u8(x);
}

static inline void round_function_256(areion_word_t *x0, areion_word_t *x1, int i)
{
    areion_word_t rc0 = round_constant_0(i);
    areion_word_t rc1 = round_constant_1(i);
    if (i == 0) {
        *x1 = areion_A2(areion_A1(areion_A1(*x0, rc0), rc1), *x1);
        *x0 = areion_A2(*x0, rc0);
    } else if (i < 9) {
        *x1 = areion_A2(areion_A1(areion_A3(*x0), rc1), *x1);
    } else {
        *x1 = areion_xor(areion_A1(areion_A3(*x0), rc1), *x1);
    }
}

static inline void inv_round_function_256(areion_word_t *x0, areion_word_t *x1, int i)
{
    areion_word_t rc0 = round_constant_0(i);
    areion_word_t rc1 = round_constant_1(i);
    *x1 = areion_xor(areion_A1(areion_A3(*x0), rc1), *x1);
    *x0 = areion_A4(*x0, rc0);
}

static inline void round_function_512(areion_word_t *x0, areion_word_t *x1, areion_word_t *x2, areion_word_t *x3, int i)
{
    areion_word_t rc0 = round_constant_0(i);
    areion_word_t rc1 = round_constant_1(i);
    if (i == 0) {
        *x1 = areion_A2(areion_A1(*x0, rc0), *x1);
        *x3 = areion_A2(areion_A1(*x2, rc0), *x3);
        *x0 = areion_A2(*x0, rc0);
        *x2 = areion_A1(areion_A2(*x2, rc0), rc1);
    } else if (i < 14) {
        *x1 = areion_A2(areion_A3(*x0), *x1);
        *x3 = areion_A2(areion_A3(*x2), *x3);
        *x2 = areion_A1(*x2, rc1);
    } else {
        *x1 = areion_xor(areion_A3(*x0), *x1);
        *x3 = areion_xor(areion_A3(*x2), *x3);
        *x2 = areion_A1(*x2, rc1);
    }
}

static inline void inv_round_function_512(areion_word_t *x0, areion_word_t *x1, areion_word_t *x2, areion_word_t *x3, int i)
{
    areion_word_t rc0 = round_constant_0(i);
    areion_word_t rc1 = round_constant_1(i);
    *x1 = areion_xor(areion_A3(*x0), *x1);
    *x0 = areion_A4(*x0, rc0);
    *x2 = areion_xor(areion_A4(areion_A5(*x2), rc0), rc1);
    *x3 = areion_xor(areion_A3(*x2), *x3);
    *x2 = areion_A4(*x2, rc0);
}

static inline void perm_256(areion_word_t *x0, areion_word_t *x1)
{
    for (int i = 0; i < 10; i += 2) {
        round_function_256(x0, x1, i);
        round_function_256(x1, x0, i + 1);
    }
}

static inline void inv_perm_256(areion_word_t *x0, areion_word_t *x1)
{
    for (int i = 0; i < 10; i += 2) {
        inv_round_function_256(x1, x0, 9 - i);
        inv_round_function_256(x0, x1, 8 - i);
    }
}

static inline void perm_512(areion_word_t *x0, areion_word_t *x1, areion_word_t *x2, areion_word_t *x3)
{
    for (int i = 0; i < 12; i += 4) {
        round_function_512(x0, x1, x2, x3, i + 0);
        round_function_512(x1, x2, x3, x0, i + 1);
        round_function_512(x2, x3, x0, x1, i + 2);
        round_function_512(x3, x0, x1, x2, i + 3);
    }
    round_function_512(x0, x1, x2, x3, 12);
    round_function_512(x1, x2, x3, x0, 13);
    round_function_512(x2, x3, x0, x1, 14);
    areion_word_t t = *x0;
    *x0 = *x3;
    *x3 = *x2;
    *x2 = *x1;
    *x1 = t;
}

static inline void inv_perm_512(areion_word_t *x0, areion_word_t *x1, areion_word_t *x2, areion_word_t *x3)
{
    areion_word_t t = *x0;
    *x0 = *x1;
    *x1 = *x2;
    *x2 = *x3;
    *x3 = t;
    inv_round_function_512(x2, x3, x0, x1, 14);
    inv_round_function_512(x1, x2, x3, x0, 13);
    inv_round_function_512(x0, x1, x2, x3, 12);
    for (int i = 0; i < 12; i += 4) {
        inv_round_function_512(x3, x0, x1, x2, 11 - i);
        inv_round_function_512(x2, x3, x0, x1, 10 - i);
        inv_round_function_512(x1, x2, x3, x0,  9 - i);
        inv_round_function_512(x0, x1, x2, x3,  8 - i);
    }
}

#endif
