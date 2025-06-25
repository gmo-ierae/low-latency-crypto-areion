/* Copyright (c) 2025 GMO Cybersecurity by Ierae, Inc. All rights reserved. */
/* This software is implemented based on the algorithms designed in the following research paper. */
/* see: https://eprint.iacr.org/2023/794 */

#include <stdint.h>

#include "impl-ref.h"
#include "private/areion-private.h"

void permute_areion_256_ref(areion_word_t dst[2], const areion_word_t src[2])
{
    areion_word_t x0 = src[0];
    areion_word_t x1 = src[1];
    perm_256(&x0, &x1);
    dst[0] = x0;
    dst[1] = x1;
}

void inverse_areion_256_ref(areion_word_t dst[2], const areion_word_t src[2])
{
    areion_word_t x0 = src[0];
    areion_word_t x1 = src[1];
    inv_perm_256(&x0, &x1);
    dst[0] = x0;
    dst[1] = x1;
}

void permute_areion_512_ref(areion_word_t dst[4], const areion_word_t src[4])
{
    areion_word_t x0 = src[0];
    areion_word_t x1 = src[1];
    areion_word_t x2 = src[2];
    areion_word_t x3 = src[3];
    perm_512(&x0, &x1, &x2, &x3);
    dst[0] = x0;
    dst[1] = x1;
    dst[2] = x2;
    dst[3] = x3;
}

void inverse_areion_512_ref(areion_word_t dst[4], const areion_word_t src[4])
{
    areion_word_t x0 = src[0];
    areion_word_t x1 = src[1];
    areion_word_t x2 = src[2];
    areion_word_t x3 = src[3];
    inv_perm_512(&x0, &x1, &x2, &x3);
    dst[0] = x0;
    dst[1] = x1;
    dst[2] = x2;
    dst[3] = x3;
}

void permute_areion_256u8_ref(uint8_t dst[32], const uint8_t src[32])
{
    areion_word_t x[2];
    areion_word_t y[2];
    areion_load_256(x, src);
    permute_areion_256(y, x);
    areion_store_256(dst, y);
}

void inverse_areion_256u8_ref(uint8_t dst[32], const uint8_t src[32])
{
    areion_word_t x[2];
    areion_word_t y[2];
    areion_load_256(x, src);
    inverse_areion_256(y, x);
    areion_store_256(dst, y);
}

void permute_areion_512u8_ref(uint8_t dst[64], const uint8_t src[64])
{
    areion_word_t x[4];
    areion_word_t y[4];
    areion_load_512(x, src);
    permute_areion_512(y, x);
    areion_store_512(dst, y);
}

void inverse_areion_512u8_ref(uint8_t dst[64], const uint8_t src[64])
{
    areion_word_t x[4];
    areion_word_t y[4];
    areion_load_512(x, src);
    inverse_areion_512(y, x);
    areion_store_512(dst, y);
}
