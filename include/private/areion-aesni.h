/* Copyright (c) 2025 GMO Cybersecurity by Ierae, Inc. All rights reserved. */

#ifndef AREION_AESNI_H
#define AREION_AESNI_H

#include <immintrin.h>
#include "areion-const.h"

/*
static inline void print_word(const char *msg, areion_word_t x)
{
    printf("%s %08X %08X %08X %08X\n", msg,
        _mm_extract_epi32(x, 0),
        _mm_extract_epi32(x, 1),
        _mm_extract_epi32(x, 2),
        _mm_extract_epi32(x, 3)
    );
}
*/

static inline void areion_load_256(areion_word_t dst[2], const uint8_t src[32])
{
    const __m128i_u *src_p = (const __m128i_u *)src;
    dst[0] = _mm_loadu_si128(&src_p[0]);
    dst[1] = _mm_loadu_si128(&src_p[1]);
}

static inline void areion_store_256(uint8_t dst[32], const areion_word_t src[2])
{
    __m128i_u *dst_p = (__m128i_u *)dst;
    _mm_storeu_si128(&dst_p[0], src[0]);
    _mm_storeu_si128(&dst_p[1], src[1]);
}

static inline void areion_load_512(areion_word_t dst[4], const uint8_t src[64])
{
    const __m128i_u *src_p = (const __m128i_u *)src;
    dst[0] = _mm_loadu_si128(&src_p[0]);
    dst[1] = _mm_loadu_si128(&src_p[1]);
    dst[2] = _mm_loadu_si128(&src_p[2]);
    dst[3] = _mm_loadu_si128(&src_p[3]);
}

static inline void areion_store_512(uint8_t dst[64], const areion_word_t src[4])
{
    __m128i_u *dst_p = (__m128i_u *)dst;
    _mm_storeu_si128(&dst_p[0], src[0]);
    _mm_storeu_si128(&dst_p[1], src[1]);
    _mm_storeu_si128(&dst_p[2], src[2]);
    _mm_storeu_si128(&dst_p[3], src[3]);
}

static inline areion_word_t areion_xor(areion_word_t x, areion_word_t y)
{
    return _mm_xor_si128(x, y);
}

static inline uint64_t areion_extract0_64(areion_word_t x)
{
    return _mm_extract_epi64(x, 0);
}

static inline uint64_t areion_extract1_64(areion_word_t x)
{
    return _mm_extract_epi64(x, 1);
}

static inline areion_word_t round_constant_0(int i)
{
    uint32_t a = RC[4 * i + 0];
    uint32_t b = RC[4 * i + 1];
    uint32_t c = RC[4 * i + 2];
    uint32_t d = RC[4 * i + 3];
    return _mm_setr_epi32(d, c, b, a);
}

static inline areion_word_t round_constant_1(int i)
{
    return _mm_setr_epi32(0, 0, 0, 0);
}

static inline void round_function_256(areion_word_t *x0, areion_word_t *x1, int i)
{
    areion_word_t rc0 = round_constant_0(i);
    areion_word_t rc1 = round_constant_1(i);
    *x1 = _mm_aesenc_si128(_mm_aesenc_si128(*x0, rc0), *x1);
    *x0 = _mm_aesenclast_si128(*x0, rc1);
}

static inline void inv_round_function_256(areion_word_t *x0, areion_word_t *x1, int i)
{
    areion_word_t rc0 = round_constant_0(i);
    areion_word_t rc1 = round_constant_1(i);
    *x0 = _mm_aesdeclast_si128(*x0, rc1);
    *x1 = _mm_aesenc_si128(_mm_aesenc_si128(*x0, rc0), *x1);
}

static inline void round_function_512(areion_word_t *x0, areion_word_t *x1, areion_word_t *x2, areion_word_t *x3, int i)
{
    areion_word_t rc0 = round_constant_0(i);
    areion_word_t rc1 = round_constant_1(i);
    *x1 = _mm_aesenc_si128(*x0, *x1);
    *x3 = _mm_aesenc_si128(*x2, *x3);
    *x0 = _mm_aesenclast_si128(*x0, rc1);
    *x2 = _mm_aesenc_si128(_mm_aesenclast_si128(*x2, rc0), rc1);
}

static inline void inv_round_function_512(areion_word_t *x0, areion_word_t *x1, areion_word_t *x2, areion_word_t *x3, int i)
{
    areion_word_t rc0 = round_constant_0(i);
    areion_word_t rc1 = round_constant_1(i);
    *x0 = _mm_aesdeclast_si128(*x0, rc1);
    *x2 = _mm_aesdeclast_si128(_mm_aesimc_si128(*x2), rc0);
    *x2 = _mm_aesdeclast_si128(*x2, rc1);
    *x1 = _mm_aesenc_si128(*x0, *x1);
    *x3 = _mm_aesenc_si128(*x2, *x3);
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
