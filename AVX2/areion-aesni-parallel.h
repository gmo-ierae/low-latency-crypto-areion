/* Copyright (c) 2025 GMO Cybersecurity by Ierae, Inc. All rights reserved. */

#ifndef AREION_AESNI_PARALLEL_H
#define AREION_AESNI_PARALLEL_H

#include <immintrin.h>
#include "private/areion-const.h"

static inline __m128i round_constant_xmm_0(int i)
{
    uint32_t a = RC[4 * i + 0];
    uint32_t b = RC[4 * i + 1];
    uint32_t c = RC[4 * i + 2];
    uint32_t d = RC[4 * i + 3];
    return _mm_setr_epi32(d, c, b, a);
}

static inline __m128i round_constant_xmm_1(int i)
{
    return _mm_setr_epi32(0, 0, 0, 0);
}

static inline void round_function_256_xmm(__m128i *x0, __m128i *x1, int i)
{
    __m128i rc0 = round_constant_xmm_0(i);
    __m128i rc1 = round_constant_xmm_1(i);
    *x1 = _mm_aesenc_si128(_mm_aesenc_si128(*x0, rc0), *x1);
    *x0 = _mm_aesenclast_si128(*x0, rc1);
}

static inline void inv_round_function_256_xmm(__m128i *x0, __m128i *x1, int i)
{
    __m128i rc0 = round_constant_xmm_0(i);
    __m128i rc1 = round_constant_xmm_1(i);
    *x0 = _mm_aesdeclast_si128(*x0, rc1);
    *x1 = _mm_aesenc_si128(_mm_aesenc_si128(*x0, rc0), *x1);
}

static inline void round_function_512_xmm(__m128i *x0, __m128i *x1, __m128i *x2, __m128i *x3, int i)
{
    __m128i rc0 = round_constant_xmm_0(i);
    __m128i rc1 = round_constant_xmm_1(i);
    *x1 = _mm_aesenc_si128(*x0, *x1);
    *x3 = _mm_aesenc_si128(*x2, *x3);
    *x0 = _mm_aesenclast_si128(*x0, rc1);
    *x2 = _mm_aesenc_si128(_mm_aesenclast_si128(*x2, rc0), rc1);
}

static inline void inv_round_function_512_xmm(__m128i *x0, __m128i *x1, __m128i *x2, __m128i *x3, int i)
{
    __m128i rc0 = round_constant_xmm_0(i);
    __m128i rc1 = round_constant_xmm_1(i);
    *x0 = _mm_aesdeclast_si128(*x0, rc1);
    *x2 = _mm_aesdeclast_si128(_mm_aesimc_si128(*x2), rc0);
    *x2 = _mm_aesdeclast_si128(*x2, rc1);
    *x1 = _mm_aesenc_si128(*x0, *x1);
    *x3 = _mm_aesenc_si128(*x2, *x3);
}

static inline void perm_256_xmm_parallel(__m128i *xs, int width)
{
    for (int i = 0; i < 10; i += 2) {
        for (int w = 0; w < width; w++) {
            round_function_256_xmm(&xs[2 * w + 0], &xs[2 * w + 1], i);
        }
        for (int w = 0; w < width; w++) {
            round_function_256_xmm(&xs[2 * w + 1], &xs[2 * w + 0], i + 1);
        }
    }
}

static inline void inv_perm_256_xmm_parallel(__m128i *xs, int width)
{
    for (int i = 0; i < 10; i += 2) {
        for (int w = 0; w < width; w++) {
            inv_round_function_256_xmm(&xs[2 * w + 1], &xs[2 * w + 0], 9 - i);
        }
        for (int w = 0; w < width; w++) {
            inv_round_function_256_xmm(&xs[2 * w + 0], &xs[2 * w + 1], 8 - i);
        }
    }
}

static inline void perm_512_xmm_parallel(__m128i *xs, int width)
{
    for (int i = 0; i < 15; i += 4) {
        for (int w = 0; w < width; w++) {
            round_function_512_xmm(&xs[4 * w + 0], &xs[4 * w + 1], &xs[4 * w + 2], &xs[4 * w + 3], i);
        }
        for (int w = 0; w < width; w++) {
            round_function_512_xmm(&xs[4 * w + 1], &xs[4 * w + 2], &xs[4 * w + 3], &xs[4 * w + 0], i + 1);
        }
        for (int w = 0; w < width; w++) {
            round_function_512_xmm(&xs[4 * w + 2], &xs[4 * w + 3], &xs[4 * w + 0], &xs[4 * w + 1], i + 2);
        }
        if (i + 3 >= 15) {
            break;
        }
        for (int w = 0; w < width; w++) {
            round_function_512_xmm(&xs[4 * w + 3], &xs[4 * w + 0], &xs[4 * w + 1], &xs[4 * w + 2], i + 3);
        }
    }
    for (int w = 0; w < width; w++) {
        areion_word_t t = xs[4 * w + 0];
        xs[4 * w + 0] = xs[4 * w + 3];
        xs[4 * w + 3] = xs[4 * w + 2];
        xs[4 * w + 2] = xs[4 * w + 1];
        xs[4 * w + 1] = t;
    }
}

static inline void inv_perm_512_xmm_parallel(__m128i *xs, int width)
{
    for (int w = 0; w < width; w++) {
        areion_word_t t = xs[4 * w + 0];
        xs[4 * w + 0] = xs[4 * w + 1];
        xs[4 * w + 1] = xs[4 * w + 2];
        xs[4 * w + 2] = xs[4 * w + 3];
        xs[4 * w + 3] = t;
    }
    for (int i = 0; i < 15; i += 4) {
        for (int w = 0; w < width; w++) {
            inv_round_function_512_xmm(&xs[4 * w + 2], &xs[4 * w + 3], &xs[4 * w + 0], &xs[4 * w + 1], 14 - i);
        }
        for (int w = 0; w < width; w++) {
            inv_round_function_512_xmm(&xs[4 * w + 1], &xs[4 * w + 2], &xs[4 * w + 3], &xs[4 * w + 0], 13 - i);
        }
        for (int w = 0; w < width; w++) {
            inv_round_function_512_xmm(&xs[4 * w + 0], &xs[4 * w + 1], &xs[4 * w + 2], &xs[4 * w + 3], 12 - i);
        }
        if (i + 3 >= 15) {
            break;
        }
        for (int w = 0; w < width; w++) {
            inv_round_function_512_xmm(&xs[4 * w + 3], &xs[4 * w + 0], &xs[4 * w + 1], &xs[4 * w + 2], 11 - i);
        }
    }
}

#endif
