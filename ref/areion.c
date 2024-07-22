/* Copyright (c) 2023 GMO Cybersecurity by Ierae, Inc. All rights reserved. */
/* This software is implemented based on the algorithms designed in the following research paper. */
/* see: https://eprint.iacr.org/2023/794 */

#include <stdint.h>
#include <immintrin.h>

#include "areion.h"

/* Round Constant */
static const uint32_t RC[24*4] = {
	0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
	0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
	0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
	0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
	0x9216d5d9, 0x8979fb1b, 0xd1310ba6, 0x98dfb5ac,
	0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96,
	0xba7c9045, 0xf12c7f99, 0x24a19947, 0xb3916cf7,
	0x801f2e28, 0x58efc166, 0x36920d87, 0x1574e690,
	0xa458fea3, 0xf4933d7e, 0x0d95748f, 0x728eb658,
	0x718bcd58, 0x82154aee, 0x7b54a41d, 0xc25a59b5,
	0x9c30d539, 0x2af26013, 0xc5d1b023, 0x286085f0,
	0xca417918, 0xb8db38ef, 0x8e79dcb0, 0x603a180e,
	0x6c9e0e8b, 0xb01e8a3e, 0xd71577c1, 0xbd314b27,
	0x78af2fda, 0x55605c60, 0xe65525f3, 0xaa55ab94,
	0x57489862, 0x63e81440, 0x55ca396a, 0x2aab10b6,
	0xb4cc5c34, 0x1141e8ce, 0xa15486af, 0x7c72e993,
	0xb3ee1411, 0x636fbc2a, 0x2ba9c55d, 0x741831f6,
	0xce5c3e16, 0x9b87931e, 0xafd6ba33, 0x6c24cf5c,
	0x7a325381, 0x28958677, 0x3b8f4898, 0x6b4bb9af,
	0xc4bfe81b, 0x66282193, 0x61d809cc, 0xfb21a991,
	0x487cac60, 0x5dec8032, 0xef845d5d, 0xe98575b1,
	0xdc262302, 0xeb651b88, 0x23893e81, 0xd396acc5,
	0xf6d6ff38, 0x3f442392, 0xe0b4482a, 0x48420040,
	0x69c8f04a, 0x9e1f9b5e, 0x21c66842, 0xf6e96c9a
};

#define RC0(i) _mm_setr_epi32(RC[(i)*4+0], RC[(i)*4+1], RC[(i)*4+2], RC[(i)*4+3])
#define RC1(i) _mm_setr_epi32(0, 0, 0, 0)

/* Round Function for the 256-bit permutation */
#define Round_Function_256(x0, x1, i) do{ \
	x1 = _mm_aesenc_si128(_mm_aesenc_si128(x0, RC0(i)), x1); \
	x0 = _mm_aesenclast_si128(x0, RC1(i)); \
} while(0)

/* 256-bit permutation */
#define perm256(x0, x1) do { \
	Round_Function_256(x0, x1, 0); \
	Round_Function_256(x1, x0, 1); \
	Round_Function_256(x0, x1, 2); \
	Round_Function_256(x1, x0, 3); \
	Round_Function_256(x0, x1, 4); \
	Round_Function_256(x1, x0, 5); \
	Round_Function_256(x0, x1, 6); \
	Round_Function_256(x1, x0, 7); \
	Round_Function_256(x0, x1, 8); \
	Round_Function_256(x1, x0, 9); \
} while(0)

/* Inversed Round Function for the 256-bit permutation */
#define Inv_Round_Function_256(x0, x1, i) do { \
	x0 = _mm_aesdeclast_si128(x0, RC1(i)); \
	x1 = _mm_aesenc_si128(_mm_aesenc_si128(x0, RC0(i)), x1); \
} while(0)

/* Inversed 256-bit permutation */
#define Inv_perm256(x0, x1) do { \
	Inv_Round_Function_256(x1, x0, 9); \
	Inv_Round_Function_256(x0, x1, 8); \
	Inv_Round_Function_256(x1, x0, 7); \
	Inv_Round_Function_256(x0, x1, 6); \
	Inv_Round_Function_256(x1, x0, 5); \
	Inv_Round_Function_256(x0, x1, 4); \
	Inv_Round_Function_256(x1, x0, 3); \
	Inv_Round_Function_256(x0, x1, 2); \
	Inv_Round_Function_256(x1, x0, 1); \
	Inv_Round_Function_256(x0, x1, 0); \
} while(0)

/* Round Function for the 512-bit permutation */
#define Round_Function_512(x0, x1, x2, x3, i) do { \
	x1 = _mm_aesenc_si128(x0, x1); \
	x3 = _mm_aesenc_si128(x2, x3); \
	x0 = _mm_aesenclast_si128(x0, RC1(i)); \
	x2 = _mm_aesenc_si128(_mm_aesenclast_si128(x2, RC0(i)), RC1(i)); \
} while(0)

/* 512-bit permutation */
#define perm512(x0, x1, x2, x3) do { \
	Round_Function_512(x0, x1, x2, x3, 0); \
	Round_Function_512(x1, x2, x3, x0, 1); \
	Round_Function_512(x2, x3, x0, x1, 2); \
	Round_Function_512(x3, x0, x1, x2, 3); \
	Round_Function_512(x0, x1, x2, x3, 4); \
	Round_Function_512(x1, x2, x3, x0, 5); \
	Round_Function_512(x2, x3, x0, x1, 6); \
	Round_Function_512(x3, x0, x1, x2, 7); \
	Round_Function_512(x0, x1, x2, x3, 8); \
	Round_Function_512(x1, x2, x3, x0, 9); \
	Round_Function_512(x2, x3, x0, x1, 10); \
	Round_Function_512(x3, x0, x1, x2, 11); \
	Round_Function_512(x0, x1, x2, x3, 12); \
	Round_Function_512(x1, x2, x3, x0, 13); \
	Round_Function_512(x2, x3, x0, x1, 14); \
} while(0)

/* Inversed Round Function or the 512-bit permutation */
#define Inv_Round_Function_512(x0, x1, x2, x3, i) do { \
	x0 = _mm_aesdeclast_si128(x0, RC1(i));  \
	x2 = _mm_aesdeclast_si128(_mm_aesimc_si128(x2), RC0(i));  \
	x2 = _mm_aesdeclast_si128(x2, RC1(i));  \
	x1 = _mm_aesenc_si128(x0, x1);  \
	x3 = _mm_aesenc_si128(x2, x3);  \
} while(0)

/* Inversed 512-bit permutation */
#define Inv_perm512(x0, x1, x2, x3) do { \
	Inv_Round_Function_512(x2, x3, x0, x1, 14); \
	Inv_Round_Function_512(x1, x2, x3, x0, 13); \
	Inv_Round_Function_512(x0, x1, x2, x3, 12); \
	Inv_Round_Function_512(x3, x0, x1, x2, 11); \
	Inv_Round_Function_512(x2, x3, x0, x1, 10); \
	Inv_Round_Function_512(x1, x2, x3, x0, 9); \
	Inv_Round_Function_512(x0, x1, x2, x3, 8); \
	Inv_Round_Function_512(x3, x0, x1, x2, 7); \
	Inv_Round_Function_512(x2, x3, x0, x1, 6); \
	Inv_Round_Function_512(x1, x2, x3, x0, 5); \
	Inv_Round_Function_512(x0, x1, x2, x3, 4); \
	Inv_Round_Function_512(x3, x0, x1, x2, 3); \
	Inv_Round_Function_512(x2, x3, x0, x1, 2); \
	Inv_Round_Function_512(x1, x2, x3, x0, 1); \
	Inv_Round_Function_512(x0, x1, x2, x3, 0); \
} while(0)

void permute_areion_256(__m128i dst[2], const __m128i src[2])
{
    __m128i x0 = src[0];
    __m128i x1 = src[1];
    perm256(x0, x1);
    dst[0] = x0;
    dst[1] = x1;
}

void inverse_areion_256(__m128i dst[2], const __m128i src[2])
{
    __m128i x0 = src[0];
    __m128i x1 = src[1];
    Inv_perm256(x0, x1);
    dst[0] = x0;
    dst[1] = x1;
}

void permute_areion_512(__m128i dst[4], const __m128i src[4])
{
    __m128i x0 = src[0];
    __m128i x1 = src[1];
    __m128i x2 = src[2];
    __m128i x3 = src[3];
    perm512(x0, x1, x2, x3);
    dst[0] = x0;
    dst[1] = x1;
    dst[2] = x2;
    dst[3] = x3;
}

void inverse_areion_512(__m128i dst[4], const __m128i src[4])
{
    __m128i x0 = src[0];
    __m128i x1 = src[1];
    __m128i x2 = src[2];
    __m128i x3 = src[3];
    Inv_perm512(x0, x1, x2, x3);
    dst[0] = x0;
    dst[1] = x1;
    dst[2] = x2;
    dst[3] = x3;
}

void permute_areion_256u8(uint8_t dst[32], const uint8_t src[32])
{
    __m128i x[2] = {
        _mm_loadu_si128((const __m128i*)&src[0]),
        _mm_loadu_si128((const __m128i*)&src[16])
    };
    __m128i y[2];
    permute_areion_256(y, x);
    _mm_storeu_si128((__m128i*)&dst[0], y[0]);
    _mm_storeu_si128((__m128i*)&dst[16], y[1]);
}

void inverse_areion_256u8(uint8_t dst[32], const uint8_t src[32])
{
    __m128i x[2] = {
        _mm_loadu_si128((const __m128i*)&src[0]),
        _mm_loadu_si128((const __m128i*)&src[16])
    };
    __m128i y[2];
    inverse_areion_256(y, x);
    _mm_storeu_si128((__m128i*)&dst[0], y[0]);
    _mm_storeu_si128((__m128i*)&dst[16], y[1]);
}

void permute_areion_512u8(uint8_t dst[64], const uint8_t src[64])
{
    __m128i x[4] = {
        _mm_loadu_si128((const __m128i*)&src[0]),
        _mm_loadu_si128((const __m128i*)&src[16]),
        _mm_loadu_si128((const __m128i*)&src[32]),
        _mm_loadu_si128((const __m128i*)&src[48])
    };
    __m128i y[4];
    permute_areion_512(y, x);
    _mm_storeu_si128((__m128i*)&dst[0], y[0]);
    _mm_storeu_si128((__m128i*)&dst[16], y[1]);
    _mm_storeu_si128((__m128i*)&dst[32], y[2]);
    _mm_storeu_si128((__m128i*)&dst[48], y[3]);
}

void inverse_areion_512u8(uint8_t dst[64], const uint8_t src[64])
{
    __m128i x[4] = {
        _mm_loadu_si128((const __m128i*)&src[0]),
        _mm_loadu_si128((const __m128i*)&src[16]),
        _mm_loadu_si128((const __m128i*)&src[32]),
        _mm_loadu_si128((const __m128i*)&src[48])
    };
    __m128i y[4];
    inverse_areion_512(y, x);
    _mm_storeu_si128((__m128i*)&dst[0], y[0]);
    _mm_storeu_si128((__m128i*)&dst[16], y[1]);
    _mm_storeu_si128((__m128i*)&dst[32], y[2]);
    _mm_storeu_si128((__m128i*)&dst[48], y[3]);
}
