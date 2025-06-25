/*
    OPP - MEM AEAD source code package

    :copyright: (c) 2015 by Philipp Jovanovic and Samuel Neves
    :license: Creative Commons CC0 1.0
*/
#include <limits.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "areion.h"

#define OPP_W 64                  /* word size */
#define OPP_T (OPP_W * 2)         /* tag size */
#define OPP_N (OPP_W * 2)         /* nonce size */
#define OPP_K (OPP_W * 2)         /* key size */
#define OPP_B 256                 /* permutation width */
#define OPP_W_NUM (OPP_B / OPP_W) /* the number of words for permutation width */

#define branch 2                /* branch number */
#define perm_W (OPP_B / branch) /* permutation word size */

#define parallel 8

/* Round Constant */
static const uint32_t RC[15*4] = {
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
};

#define RC0(i) _mm_setr_epi32(RC[(i)*4+3], RC[(i)*4+2], RC[(i)*4+1], RC[(i)*4+0])
#define RC1(i) _mm_setr_epi32(0, 0, 0, 0)

/* Round Function for the 256-bit permutation */
#define R(x0, x1, i) do {                                    \
  x1 = _mm_aesenc_si128(_mm_aesenc_si128(x0, RC0(i)), x1);   \
  x0 = _mm_aesenclast_si128(x0, RC1(i));                     \
} while(0)

/* 256-bit permutation */
#define V1_perm(x0, x1) do {  \
    R(x0, x1, 0); \
    R(x1, x0, 1); \
    R(x0, x1, 2); \
    R(x1, x0, 3); \
    R(x0, x1, 4); \
    R(x1, x0, 5); \
    R(x0, x1, 6); \
    R(x1, x0, 7); \
    R(x0, x1, 8); \
    R(x1, x0, 9); \
} while(0)

#define V2_perm(x) do {  \
    V1_perm(x[0], x[1]); \
    V1_perm(x[2], x[3]); \
} while(0)

#define V4_perm(x) do {  \
    V1_perm(x[0], x[1]); \
    V1_perm(x[2], x[3]); \
    V1_perm(x[4], x[5]); \
    V1_perm(x[6], x[7]); \
} while(0)

#define V8_perm(x) do {    \
    V1_perm(x[ 0], x[ 1]); \
    V1_perm(x[ 2], x[ 3]); \
    V1_perm(x[ 4], x[ 5]); \
    V1_perm(x[ 6], x[ 7]); \
    V1_perm(x[ 8], x[ 9]); \
    V1_perm(x[10], x[11]); \
    V1_perm(x[12], x[13]); \
    V1_perm(x[14], x[15]); \
} while(0)

/*
#define V1_perm(x) do {  \
    R(x[0], x[1], 0); \
    R(x[1], x[0], 1); \
    R(x[0], x[1], 2); \
    R(x[1], x[0], 3); \
    R(x[0], x[1], 4); \
    R(x[1], x[0], 5); \
    R(x[0], x[1], 6); \
    R(x[1], x[0], 7); \
} while(0)
*/

/* Inversed Round Function for the 256-bit permutation */
#define Inv_R(x0, x1, i) do {                                \
  x0 = _mm_aesdeclast_si128(x0, RC1(i));                     \
  x1 = _mm_aesenc_si128(_mm_aesenc_si128(x0, RC0(i)), x1);   \
} while(0)

/* 256-bit inversed permutation */
#define V1_Inv_perm(x0, x1) do {  \
    Inv_R(x1, x0, 9); \
    Inv_R(x0, x1, 8); \
    Inv_R(x1, x0, 7); \
    Inv_R(x0, x1, 6); \
    Inv_R(x1, x0, 5); \
    Inv_R(x0, x1, 4); \
    Inv_R(x1, x0, 3); \
    Inv_R(x0, x1, 2); \
    Inv_R(x1, x0, 1); \
    Inv_R(x0, x1, 0); \
} while(0)

#define V2_Inv_perm(x) do {  \
    V1_Inv_perm(x[0], x[1]); \
    V1_Inv_perm(x[2], x[3]); \
} while(0)

#define V4_Inv_perm(x) do {  \
    V1_Inv_perm(x[0], x[1]); \
    V1_Inv_perm(x[2], x[3]); \
    V1_Inv_perm(x[4], x[5]); \
    V1_Inv_perm(x[6], x[7]); \
} while(0)

#define V8_Inv_perm(x) do {    \
    V1_Inv_perm(x[ 0], x[ 1]); \
    V1_Inv_perm(x[ 2], x[ 3]); \
    V1_Inv_perm(x[ 4], x[ 5]); \
    V1_Inv_perm(x[ 6], x[ 7]); \
    V1_Inv_perm(x[ 8], x[ 9]); \
    V1_Inv_perm(x[10], x[11]); \
    V1_Inv_perm(x[12], x[13]); \
    V1_Inv_perm(x[14], x[15]); \
} while(0)

/*
#define V1_Inv_perm(x) do {  \
    Inv_R(x[1], x[0], 7); \
    Inv_R(x[0], x[1], 6); \
    Inv_R(x[1], x[0], 5); \
    Inv_R(x[0], x[1], 4); \
    Inv_R(x[1], x[0], 3); \
    Inv_R(x[0], x[1], 2); \
    Inv_R(x[1], x[0], 1); \
    Inv_R(x[0], x[1], 0); \
} while(0)
*/

#define BYTES(X) (((X) + 7) / 8)
#define WORDS(X) (((X) + (OPP_W - 1)) / OPP_W)

#define ADD128(A, B) _mm_add_epi64((A), (B))
#define SUB128(A, B) _mm_sub_epi64((A), (B))
#define XOR128(A, B) _mm_xor_si128((A), (B))
#define  OR128(A, B)  _mm_or_si128((A), (B))
#define AND128(A, B) _mm_and_si128((A), (B))
#define SHL128(A, B) _mm_slli_epi64((A), (B))
#define SHR128(A, B) _mm_srli_epi64((A), (B))

#define ADD256(A, B) _mm256_add_epi64((A), (B))
#define SUB256(A, B) _mm256_sub_epi64((A), (B))
#define XOR256(A, B) _mm256_xor_si256((A), (B))
#define  OR256(A, B)  _mm256_or_si256((A), (B))
#define AND256(A, B) _mm256_and_si256((A), (B))
#define SHL256(A, B) _mm256_slli_epi64((A), (B))
#define SHR256(A, B) _mm256_srli_epi64((A), (B))

#define ROTL64(X, C) ( ((X) << (C)) | ((X) >> (OPP_W - (C))) )
#define ROTR64(X, C) ( ((X) >> (C)) | ((X) << (OPP_W - (C))) )

#define LOADU128(X) _mm_loadu_si128((const __m128i *)((X)))
#define STOREU128(X, V) _mm_storeu_si128((__m128i *)((X)), (V))

#define LOADU256(X) _mm256_loadu_si256((const __m256i *)((X)))
#define STOREU256(X, V) _mm256_storeu_si256((__m256i *)((X)), (V))

/* 
  b = 256, w = 64, n = 4 
  Ref. Table 1 in [Granger et al., EUROCRYPT'16]

  alpha(x) = phi(x)
*/
#define V1_ALPHA_UPDATE(L) do {            \
  L[4] = ROTL64(L[0], 3) ^ (L[3] >> 5); \
  STOREU256(&L[ 0], LOADU256(&L[ 1]));  \
} while(0)

#define V2_ALPHA_UPDATE_1(L) do {       \
  L[4] = ROTL64(L[0], 3) ^ (L[3] >> 5); \
  L[5] = ROTL64(L[1], 3) ^ (L[4] >> 5); \
} while(0)

#define V2_ALPHA_UPDATE_2(L) do {      \
  STOREU256(&L[ 0], LOADU256(&L[ 2])); \
} while(0)

#define V4_ALPHA_UPDATE_1(L) do {       \
  L[4] = ROTL64(L[0], 3) ^ (L[3] >> 5); \
  L[5] = ROTL64(L[1], 3) ^ (L[4] >> 5); \
  L[6] = ROTL64(L[2], 3) ^ (L[5] >> 5); \
  L[7] = ROTL64(L[3], 3) ^ (L[6] >> 5); \
} while(0)

#define V4_ALPHA_UPDATE_2(L) do {      \
  STOREU256(&L[ 0], LOADU256(&L[ 4])); \
} while(0)

#define V8_ALPHA_UPDATE_1(L) do {         \
  L[ 4] = ROTL64(L[0], 3) ^ (L[ 3] >> 5); \
  L[ 5] = ROTL64(L[1], 3) ^ (L[ 4] >> 5); \
  L[ 6] = ROTL64(L[2], 3) ^ (L[ 5] >> 5); \
  L[ 7] = ROTL64(L[3], 3) ^ (L[ 6] >> 5); \
  L[ 8] = ROTL64(L[4], 3) ^ (L[ 7] >> 5); \
  L[ 9] = ROTL64(L[5], 3) ^ (L[ 8] >> 5); \
  L[10] = ROTL64(L[6], 3) ^ (L[ 9] >> 5); \
  L[11] = ROTL64(L[7], 3) ^ (L[10] >> 5); \
} while(0)

#define V8_ALPHA_UPDATE_2(L) do {      \
  STOREU256(&L[ 0], LOADU256(&L[ 8])); \
} while(0)

/* 
  b = 256, w = 64, n = 4 
  Ref. Table 1 in [Granger et al., EUROCRYPT'16]

  beta(x) = phi(x) ^ x
*/
#define V1_BETA_UPDATE(L) do {                                    \
  L[4] = ROTL64(L[0], 3) ^ (L[3] >> 5);                           \
  STOREU256(&L[ 0], XOR256(LOADU256(&L[ 0]), LOADU256(&L[ 1])));  \
} while(0)

/* 
  b = 256, w = 64, n = 4 
  Ref. Table 1 in [Granger et al., EUROCRYPT'16]

  gamma(x) = phi^2(x) ^ phi(x) ^ x
*/
#define V1_GAMMA_UPDATE(L) do {         \
  int i;                                \
  L[4] = ROTL64(L[0], 3) ^ (L[3] >> 5); \
  L[5] = ROTL64(L[1], 3) ^ (L[4] >> 5); \
  STOREU256(&L[ 0], XOR256(XOR256(LOADU256(&L[ 0]), LOADU256(&L[ 1])), LOADU256(&L[ 2]))); \
} while(0)

/*
#define GAMMA_UPDATE(L) do {              \
  int i;                                  \
  L[4] = ROTL64(L[0], 11) ^ (L[3] << 13); \
  L[5] = ROTL64(L[1], 11) ^ (L[4] << 13); \
  for(i = 0; i < 4; ++i) {                \
    L[i] ^= L[i+1] ^ L[i+2];              \
  }                                       \
} while(0)
*/

#define ZERO_BLOCK(B) do {      \
  int i;                        \
  for(i = 0; i < branch; ++i) { \
  	B[i] = _mm_setzero_si128(); \
  }                             \
} while(0)

#define V1_LOAD_BLOCK(B, m) do {          \
  int i;                                  \
  for(i = 0; i < branch; ++i) {           \
    B[i] = LOADU128(&m[perm_W / 8 * i]);  \
  }                                       \
} while(0)

#define V2_LOAD_BLOCK(B, m) do {         \
  int i;                                 \
  for(i = 0; i < branch*2; ++i) {        \
    B[i] = LOADU128(&m[perm_W / 8 * i]); \
  }                                      \
} while(0)

#define V4_LOAD_BLOCK(B, m) do {         \
  int i;                                 \
  for(i = 0; i < branch*4; ++i) {        \
    B[i] = LOADU128(&m[perm_W / 8 * i]); \
  }                                      \
} while(0)

#define V8_LOAD_BLOCK(B, m) do {         \
  int i;                                 \
  for(i = 0; i < branch*8; ++i) {        \
    B[i] = LOADU128(&m[perm_W / 8 * i]); \
  }                                      \
} while(0)

#define V1_STORE_BLOCK(c, B) do {         \
  int i;                                  \
  for(i = 0; i < branch; ++i) {           \
    STOREU128(&c[perm_W / 8 * i], B[i]);  \
  }                                       \
} while(0)

#define V2_STORE_BLOCK(c, B) do {         \
  int i;                                  \
  for(i = 0; i < branch*2; ++i) {         \
    STOREU128(&c[perm_W / 8 * i], B[i]);  \
  }                                       \
} while(0)

#define V4_STORE_BLOCK(c, B) do {         \
  int i;                                  \
  for(i = 0; i < branch*4; ++i) {         \
    STOREU128(&c[perm_W / 8 * i], B[i]);  \
  }                                       \
} while(0)

#define V8_STORE_BLOCK(c, B) do {         \
  int i;                                  \
  for(i = 0; i < branch*8; ++i) {         \
    STOREU128(&c[perm_W / 8 * i], B[i]);  \
  }                                       \
} while(0)

#define V1_XOR_MASK(B, L) do {              \
  int i;                                    \
  for(i = 0; i < branch; ++i) {             \
    B[i] = XOR128(B[i], LOADU128(&L[2*i])); \
  }                                         \
} while(0)

#define V2_XOR_MASK(B, L) do {                                  \
  int i, j;                                                     \
  for(i = 0; i < 2; ++i) {                                      \
    for(j = 0; j < branch; ++j) {                               \
      B[(2*i)+j] = XOR128(B[(2*i)+j], LOADU128(&L[i+(2*j)]));   \
    }                                                           \
  }                                                             \
} while(0)

#define V4_XOR_MASK(B, L) do {                                  \
  int i, j;                                                     \
  for(i = 0; i < 4; ++i) {                                      \
    for(j = 0; j < branch; ++j) {                               \
      B[(2*i)+j] = XOR128(B[(2*i)+j], LOADU128(&L[i+(2*j)]));   \
    }                                                           \
  }                                                             \
} while(0)

#define V8_XOR_MASK(B, L) do {                                  \
  int i, j;                                                     \
  for(i = 0; i < 8; ++i) {                                      \
    for(j = 0; j < branch; ++j) {                               \
      B[(2*i)+j] = XOR128(B[(2*i)+j], LOADU128(&L[i+(2*j)]));   \
    }                                                           \
  }                                                             \
} while(0)

#define V1_ACCUMULATE(T, B) do { \
  int i;                         \
  for(i = 0; i < branch; ++i) {  \
    T[i] = XOR128(B[i], T[i]);   \
  }                              \
} while(0)

#define V2_ACCUMULATE(T, B) do {  \
  int i;                          \
  for(i = 0; i < branch; ++i) {   \
    T[i] = XOR128(B[i  ], T[i]);  \
    T[i] = XOR128(B[i+2], T[i]);  \
  }                               \
} while(0)

#define V4_ACCUMULATE(T, B) do {  \
  int i;                          \
  for(i = 0; i < branch; ++i) {   \
    T[i] = XOR128(B[i  ], T[i]);  \
    T[i] = XOR128(B[i+2], T[i]);  \
    T[i] = XOR128(B[i+4], T[i]);  \
    T[i] = XOR128(B[i+6], T[i]);  \
  }                               \
} while(0)

#define V8_ACCUMULATE(T, B) do {  \
  int i;                          \
  for(i = 0; i < branch; ++i) {   \
    T[i] = XOR128(B[i   ], T[i]); \
    T[i] = XOR128(B[i+ 2], T[i]); \
    T[i] = XOR128(B[i+ 4], T[i]); \
    T[i] = XOR128(B[i+ 6], T[i]); \
    T[i] = XOR128(B[i+ 8], T[i]); \
    T[i] = XOR128(B[i+10], T[i]); \
    T[i] = XOR128(B[i+12], T[i]); \
    T[i] = XOR128(B[i+14], T[i]); \
  }                               \
} while(0)

/* Masked Even-Mansour (MEM) construction */
#define V1_MEM(B, L) do { \
  V1_XOR_MASK(B, L);      \
  V1_perm(B[0], B[1]);    \
  V1_XOR_MASK(B, L);      \
} while(0)

#define V2_MEM(B, L) do { \
  V2_XOR_MASK(B, L);      \
  V2_perm(B);             \
  V2_XOR_MASK(B, L);      \
} while(0)

#define V4_MEM(B, L) do { \
  V4_XOR_MASK(B, L);      \
  V4_perm(B);             \
  V4_XOR_MASK(B, L);      \
} while(0)

#define V8_MEM(B, L) do { \
  V8_XOR_MASK(B, L);      \
  V8_perm(B);             \
  V8_XOR_MASK(B, L);      \
} while(0)

/* Inversed Masked Even-Mansour (MEM) construction */
#define V1_Inv_MEM(B, L) do { \
  V1_XOR_MASK(B, L);       \
  V1_Inv_perm(B[0], B[1]); \
  V1_XOR_MASK(B, L);       \
} while(0)

#define V2_Inv_MEM(B, L) do { \
  V2_XOR_MASK(B, L);       \
  V2_Inv_perm(B);          \
  V2_XOR_MASK(B, L);       \
} while(0)

#define V4_Inv_MEM(B, L) do { \
  V4_XOR_MASK(B, L);       \
  V4_Inv_perm(B);          \
  V4_XOR_MASK(B, L);       \
} while(0)

#define V8_Inv_MEM(B, L) do { \
  V8_XOR_MASK(B, L);       \
  V8_Inv_perm(B);          \
  V8_XOR_MASK(B, L);       \
} while(0)



// #define PRINT_DATA

#define PARALLEL
#define DECRYPT

// #define NUMBER_OF_LOOPS 1         /* the number of trials */
//#define NUMBER_OF_LOOPS 12500000  /* the number of trials */
//#define HSIZE 256                 /* the size of associated data (bytes) */
//#define MSIZE 512                 /* the size of plaintext (bytes) */

void print128(__m128i var)
{
    uint8_t val[16];
    memcpy(val, &var, sizeof(val));
    for (int i=0; i<16; i++){
      printf("%02x", val[i]);
    }
    printf("\n");
}

/* opp_pad: padding function */
static void opp_pad(
  unsigned char * out, 
  const void * in, 
  size_t inlen) 
{
  memset(out, 0, BYTES(OPP_B));
  memcpy(out, in, inlen);
  out[inlen] = 0x01;
}

/* opp_init_mask: initial mask generation function */
static void opp_init_mask(
  uint64_t * absorb_mask, 
  uint64_t * encrypt_mask, 
  const uint8_t * key, 
  const uint8_t * nonce) 
{
  __m128i state[branch];
  state[0] = LOADU128(nonce);
  state[1] = LOADU128(key);

  V1_perm(state[0], state[1]);

  memcpy(absorb_mask, state, sizeof(state));
  memcpy(encrypt_mask, state, sizeof(state));
  V1_GAMMA_UPDATE(encrypt_mask);
}

/* opp_absorb_data: header absorbing function */
static void opp_absorb_data(
  __m128i T[branch], 
  const uint8_t * h, 
  size_t hlen, 
  uint64_t delta[OPP_W_NUM+parallel]) 
{
#ifdef PARALLEL
  while(hlen >= 8 * BYTES(OPP_B)) {
    __m128i state[branch*8];

    V8_ALPHA_UPDATE_1(delta);
    V8_LOAD_BLOCK(state, h);
    V8_MEM(state, delta);
    V8_ACCUMULATE(T, state);
    V8_ALPHA_UPDATE_2(delta);
    h    += 8 * BYTES(OPP_B);
    hlen -= 8 * BYTES(OPP_B);
  }

  while(hlen >= 4 * BYTES(OPP_B)) {
    __m128i state[branch*4];

    V4_ALPHA_UPDATE_1(delta);
    V4_LOAD_BLOCK(state, h);
    V4_MEM(state, delta);
    V4_ACCUMULATE(T, state);
    V4_ALPHA_UPDATE_2(delta);
    h    += 4 * BYTES(OPP_B);
    hlen -= 4 * BYTES(OPP_B);
  }

  while(hlen >= 2 * BYTES(OPP_B)) {
    __m128i state[branch*2];

    V2_ALPHA_UPDATE_1(delta);
    V2_LOAD_BLOCK(state, h);
    V2_MEM(state, delta);
    V2_ACCUMULATE(T, state);
    V2_ALPHA_UPDATE_2(delta);
    h    += 2 * BYTES(OPP_B);
    hlen -= 2 * BYTES(OPP_B);
  }
#endif
  while(hlen >= BYTES(OPP_B)) {
    __m128i state[branch];

    V1_LOAD_BLOCK(state, h);
    V1_MEM(state, delta);
    V1_ACCUMULATE(T, state);

    V1_ALPHA_UPDATE(delta);
    h    += BYTES(OPP_B);
    hlen -= BYTES(OPP_B);
  }

  /* handle partial final block */
  if(hlen > 0) {
    uint8_t lastblock[BYTES(OPP_B)];
    __m128i state[branch];
    V1_BETA_UPDATE(delta);
    opp_pad(lastblock, h, hlen);
    V1_LOAD_BLOCK(state, lastblock);
    V1_MEM(state, delta);
    V1_ACCUMULATE(T, state);
  }
}

/* opp_encrypt_data: encryption function */
static void opp_encrypt_data(
  __m128i T[branch], 
  uint8_t * c, 
  const uint8_t * m, 
  size_t mlen, 
  uint64_t delta[OPP_W_NUM+parallel]) 
{
#ifdef PARALLEL
  while(mlen >= 8 * BYTES(OPP_B)) {
    __m128i state[branch*8];
    V8_ALPHA_UPDATE_1(delta);
    V8_LOAD_BLOCK(state, m);
    V8_ACCUMULATE(T, state);
    V8_MEM(state, delta);
    V8_STORE_BLOCK(c, state);
    V8_ALPHA_UPDATE_2(delta);
    c    += 8 * BYTES(OPP_B);
    m    += 8 * BYTES(OPP_B);
    mlen -= 8 * BYTES(OPP_B);
  }

  while(mlen >= 4 * BYTES(OPP_B)) {
    __m128i state[branch*4];
    V4_ALPHA_UPDATE_1(delta);
    V4_LOAD_BLOCK(state, m);
    V4_ACCUMULATE(T, state);
    V4_MEM(state, delta);
    V4_STORE_BLOCK(c, state);
    V4_ALPHA_UPDATE_2(delta);
    c    += 4 * BYTES(OPP_B);
    m    += 4 * BYTES(OPP_B);
    mlen -= 4 * BYTES(OPP_B);
  }

  while(mlen >= 2 * BYTES(OPP_B)) {
    __m128i state[branch*2];
    V2_ALPHA_UPDATE_1(delta);
    V2_LOAD_BLOCK(state, m);
    V2_ACCUMULATE(T, state);
    V2_MEM(state, delta);
    V2_STORE_BLOCK(c, state);
    V2_ALPHA_UPDATE_2(delta);
    c    += 2 * BYTES(OPP_B);
    m    += 2 * BYTES(OPP_B);
    mlen -= 2 * BYTES(OPP_B);
  }
#endif
  while(mlen >= BYTES(OPP_B)) {
    __m128i state[branch];

    V1_LOAD_BLOCK(state, m);
    V1_ACCUMULATE(T, state);
    V1_MEM(state, delta);
    V1_STORE_BLOCK(c, state);

    V1_ALPHA_UPDATE(delta);
    c    += BYTES(OPP_B);
    m    += BYTES(OPP_B);
    mlen -= BYTES(OPP_B);
  }

  /* handle partial final block */
  if(mlen > 0) { 
    uint8_t lastblock[BYTES(OPP_B)];
    __m128i state[branch];
    int i;
    V1_BETA_UPDATE(delta);
    opp_pad(lastblock, m, mlen);
    ZERO_BLOCK(state);
    V1_MEM(state, delta);
    /* lastblock xor state and T xor last block */
    for(i = 0; i < branch; ++i) { 
      const __m128i M_i = LOADU128(&lastblock[perm_W / 8 * i]);
      T[i] = XOR128(T[i], M_i);
      STOREU128(&lastblock[perm_W / 8 * i], XOR128(state[i], M_i));
    }
    memcpy(c, lastblock, mlen);
  }
}

#ifdef DECRYPT
static void opp_decrypt_data(
  __m128i T[branch], 
  uint8_t * m, 
  const uint8_t * c, 
  size_t clen, 
  uint64_t delta[OPP_W_NUM+parallel]) 
{
#ifdef PARALLEL
  while(clen >= 8 * BYTES(OPP_B)) {
    __m128i state[branch*8];
    V8_ALPHA_UPDATE_1(delta);
    V8_LOAD_BLOCK(state, c);
    V8_Inv_MEM(state, delta);
    V8_ACCUMULATE(T, state);
    V8_STORE_BLOCK(m, state);
    V8_ALPHA_UPDATE_2(delta);
    m    += 8 * BYTES(OPP_B);
    c    += 8 * BYTES(OPP_B);
    clen -= 8 * BYTES(OPP_B);
  }

  while(clen >= 4 * BYTES(OPP_B)) {
    __m128i state[branch*4];
    V4_ALPHA_UPDATE_1(delta);
    V4_LOAD_BLOCK(state, c);
    V4_Inv_MEM(state, delta);
    V4_ACCUMULATE(T, state);
    V4_STORE_BLOCK(m, state);
    V4_ALPHA_UPDATE_2(delta);
    m    += 4 * BYTES(OPP_B);
    c    += 4 * BYTES(OPP_B);
    clen -= 4 * BYTES(OPP_B);
  }

  while(clen >= 2 * BYTES(OPP_B)) {
    __m128i state[branch*2];
    V2_ALPHA_UPDATE_1(delta);
    V2_LOAD_BLOCK(state, c);
    V2_Inv_MEM(state, delta);
    V2_ACCUMULATE(T, state);
    V2_STORE_BLOCK(m, state);
    V2_ALPHA_UPDATE_2(delta);
    m    += 2 * BYTES(OPP_B);
    c    += 2 * BYTES(OPP_B);
    clen -= 2 * BYTES(OPP_B);
  }
#endif
  while(clen >= BYTES(OPP_B)) {
    __m128i state[branch];

    V1_LOAD_BLOCK(state, c);
    V1_Inv_MEM(state, delta);
    V1_ACCUMULATE(T, state);
    V1_STORE_BLOCK(m, state);

    V1_ALPHA_UPDATE(delta);
    m    += BYTES(OPP_B);
    c    += BYTES(OPP_B);
    clen -= BYTES(OPP_B);
  }

  /* handle partial final block */
  if(clen > 0) { 
    uint8_t lastblock[BYTES(OPP_B)];
    __m128i state[branch];
    int i;
    V1_BETA_UPDATE(delta);
    opp_pad(lastblock, c, clen);
    ZERO_BLOCK(state);
    V1_MEM(state, delta);
    /* lastblock xor state */
    for(i = 0; i < branch; ++i) { 
      const __m128i C_i = LOADU128(&lastblock[perm_W / 8 * i]);
      STOREU128(&lastblock[perm_W / 8 * i], XOR128(state[i], C_i));
    }
    memcpy(m, lastblock, clen);
    opp_pad(lastblock, m, clen);
    for(i = 0; i < branch; ++i) { /* T xor last block */
      T[i] = XOR128(T[i], LOADU128(&lastblock[perm_W / 8 * i]));
    }
  }
}
#endif

static void opp_tag(
  __m128i * Te, 
  const __m128i * Ta, 
  uint64_t * delta) 
{
  size_t i;
  for(i = 0; i < 2; ++i) {
    V1_BETA_UPDATE(delta);
  }
  V1_MEM(Te, delta);
  V1_ACCUMULATE(Te, Ta);
}

#if defined(OPP_DEBUG)
static void print_mask(uint64_t * L) {
  int i;
  for(i = 0; i < 4; ++i) {
    printf("%016llX%c", L[i], i % 4 == 3 ? '\n' : ' ');
  }
  // printf("\n");
}

static void print_state(__m128i * state) {
// static void print_state(__m256i * state) {
  uint64_t L[16];
  int i;
  for(i = 0; i < 2; ++i) {
    STOREU128(&L[2*i], state[i]);
  }
  print_mask(L);
  printf("\n");
}
#endif

/* high level interface functions */
void encrypt_areion_256_opp(
    uint8_t *c,
    uint8_t tag[AREION_256_OPP_TAG_LEN],
    const uint8_t *h, size_t hlen,
    const uint8_t *m, size_t mlen,
    const uint8_t nonce[AREION_256_OPP_NONCE_LEN],
    const uint8_t key[AREION_256_OPP_KEY_LEN])
/*
void crypto_aead_encrypt(
    unsigned char *c, size_t *clen,
    const unsigned char *h, size_t hlen,
    const unsigned char *m, size_t mlen,
    const unsigned char *n,
    const unsigned char *k
    )*/
{
  __m128i Ta[branch] = {0};
  __m128i Te[branch] = {0};
  uint64_t absorb_mask[OPP_W_NUM+parallel];
  uint64_t encrypt_mask[OPP_W_NUM+parallel];

  opp_init_mask(absorb_mask, encrypt_mask, key, nonce);

#if defined(OPP_DEBUG)
  print_mask(absorb_mask);
  print_mask(encrypt_mask);
#endif

  opp_absorb_data(Ta, h, hlen, absorb_mask);
  opp_encrypt_data(Te, c, m, mlen, encrypt_mask);
  opp_tag(Te, Ta, encrypt_mask);

#if defined(OPP_DEBUG)
  print_state(Te);
#endif

  STOREU128(tag, Te[0]);

  // STOREU128(c + mlen + 16, Te[1]);
  // STOREU256(c + mlen, Te[0]);

#if defined(DEBUG)
  {
    int i;
    for(i = 0; i < *clen; ++i)
      printf("%02X ", c[i]);
    printf("\n");
  }
#endif
}

int decrypt_areion_256_opp(
    uint8_t *m,
    const uint8_t tag[AREION_256_OPP_TAG_LEN],
    const uint8_t *h, size_t hlen,
    const uint8_t *c, size_t clen,
    const uint8_t nonce[AREION_256_OPP_NONCE_LEN],
    const uint8_t key[AREION_256_OPP_KEY_LEN])
{
  __m128i Ta[branch] = {0};
  __m128i Te[branch] = {0};
  uint64_t absorb_mask[OPP_W_NUM+parallel];
  uint64_t encrypt_mask[OPP_W_NUM+parallel];

  opp_init_mask(absorb_mask, encrypt_mask, key, nonce);

  opp_absorb_data(Ta, h, hlen, absorb_mask);
  opp_decrypt_data(Te, m, c, clen, encrypt_mask);
  opp_tag(Te, Ta, encrypt_mask);

  Te[0] = _mm_cmpeq_epi8(Te[0], LOADU128(tag));
  return (( (_mm_movemask_epi8(Te[0]) & 0xFFFFFFFFULL) + 1) >> 16) - 1;
  /*
  Te[0] = _mm256_cmpeq_epi8(Te[0], LOADU256(c + clen - BYTES(OPP_T)));
  return (( (_mm256_movemask_epi8(Te[0]) & 0xFFFFFFFFULL) + 1) >> 32) - 1;
  */
}
