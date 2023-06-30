/* Copyright (c) 2023 GMO Cybersecurity by Ierae, Inc. All rights reserved. */

#ifndef AREION_H
#define AREION_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <immintrin.h>

//
// areion primitives
//

// 256bit areion permutation (π_256)
//
// permute one block (256 bits)
//   dst <- π_256(src)
void permute_areion_256(__m128i dst[2], const __m128i src[2]);

// 256bit areion inverse permutation (π_256 inverse)
//
// inverse permute one block (256 bits)
//   dst <- π_256^-1(src)
void inverse_areion_256(__m128i dst[2], const __m128i src[2]);


// 512bit areion permutation (π_512)
//
// permute one block (512 bits)
//   dst <- π_512(src)
void permute_areion_512(__m128i dst[4], const __m128i src[4]);

// 512bit areion inverse permutation (π_512 inverse)
//
// inverse permute one block (512 bits)
//   dst <- π_512^-1(src)
void inverse_areion_512(__m128i dst[4], const __m128i src[4]);

//
// areion primitives with uint8_t interface
//

// 256bit areion permutation (π_256)
//
// permute one block (256 bits)
//   dst <- π_256(src)
void permute_areion_256u8(uint8_t dst[32], const uint8_t src[32]);

// 256bit areion inverse permutation (π_256 inverse)
//
// inverse permute one block (256 bits)
//   dst <- π_256^-1(src)
void inverse_areion_256u8(uint8_t dst[32], const uint8_t src[32]);


// 512bit areion permutation (π_512)
//
// permute one block (512 bits)
//   dst <- π_512(src)
void permute_areion_512u8(uint8_t dst[64], const uint8_t src[64]);

// 512bit areion inverse permutation (π_512 inverse)
//
// inverse permute one block (512 bits)
//   dst <- π_512^-1(src)
void inverse_areion_512u8(uint8_t dst[64], const uint8_t src[64]);

//
// OPP mode AEAD cipher
//

#define AREION_256_OPP_TAG_LEN 16
#define AREION_256_OPP_NONCE_LEN 16
#define AREION_256_OPP_KEY_LEN 16

// encrypt function of AREION-256-OPP
//
// in
//   h, hlen: associated data
//   m, mlen: plaintext
//   nonce: nonce (128 bit)
//   key: key (128 bit)
// out
//   c: ciphertext.  need mlen bytes buffer.
//   tag: tag
void encrypt_areion_256_opp(
    uint8_t *c,
    uint8_t tag[AREION_256_OPP_TAG_LEN],
    const uint8_t *h, size_t hlen,
    const uint8_t *m, size_t mlen,
    const uint8_t nonce[AREION_256_OPP_NONCE_LEN],
    const uint8_t key[AREION_256_OPP_KEY_LEN]);

// decrypt function of AREION-256-OPP
//
// in
//   h, hlen: associated data
//   c, clen: ciphertext
//   nonce: nonce (128 bit)
//   key: key (128 bit)
//   tag: tag
// out
//   m: plaintext.  need clen bytes buffer.
// return
//   true if tag is verified successfully, otherwise false
int decrypt_areion_256_opp(
    uint8_t *m,
    const uint8_t tag[AREION_256_OPP_TAG_LEN],
    const uint8_t *h, size_t hlen,
    const uint8_t *c, size_t clen,
    const uint8_t nonce[AREION_256_OPP_NONCE_LEN],
    const uint8_t key[AREION_256_OPP_KEY_LEN]);

#define AREION_512_OPP_TAG_LEN 16
#define AREION_512_OPP_NONCE_LEN 16
#define AREION_512_OPP_KEY_LEN 16

// encrypt function of AREION-512-OPP
//
// in
//   h, hlen: associated data
//   m, mlen: plaintext
//   nonce: nonce (128 bit)
//   key: key (128 bit)
// out
//   c: ciphertext.  need mlen bytes buffer.
//   tag: tag
void encrypt_areion_512_opp(
    uint8_t *c,
    uint8_t tag[AREION_512_OPP_TAG_LEN],
    const uint8_t *h, size_t hlen,
    const uint8_t *m, size_t mlen,
    const uint8_t nonce[AREION_512_OPP_NONCE_LEN],
    const uint8_t key[AREION_512_OPP_KEY_LEN]);

// decrypt function of AREION-512-OPP
//
// in
//   h, hlen: associated data
//   c, clen: ciphertext
//   nonce: nonce (128 bit)
//   key: key (128 bit)
//   tag: tag
// out
//   m: plaintext.  need clen bytes buffer.
// return
//   true if tag is verified successfully, otherwise false
int decrypt_areion_512_opp(
    uint8_t *m,
    const uint8_t tag[AREION_512_OPP_TAG_LEN],
    const uint8_t *h, size_t hlen,
    const uint8_t *c, size_t clen,
    const uint8_t nonce[AREION_512_OPP_NONCE_LEN],
    const uint8_t key[AREION_512_OPP_KEY_LEN]);


// OPP init/update/final API

typedef struct areion_256_opp_t areion_256_opp_t;

areion_256_opp_t *alloc_areion_256_opp();
void free_areion_256_opp(areion_256_opp_t *state);

// initialize AREION-256-OPP state
//
// in
//   enc: true if encrypt, false if decrypt
//   nonce: nonce (128 bit)
//   key: key (128 bit)
// in/out
//   state: AREION-256-OPP state
bool initialize_areion_256_opp(bool enc, const uint8_t nonce[AREION_256_OPP_NONCE_LEN], const uint8_t key[AREION_256_OPP_KEY_LEN], areion_256_opp_t *state);

// update AREION-256-OPP state
//
// in
//   in, ilen: input message
//   olimit: output buffer size.  olimit must be >= (LI & ~31) - LO
//           where LI = total input length passed includes ilen
//                 LO = total output length already returned
//           unused if out == NULL
// out
//   out: output buffer.  NULL if input message is associated data.
//   olen:  bytes count written
// in/out
//   state: AREION-256-OPP state
bool update_areion_256_opp(uint8_t *out, size_t *olen, size_t olimit, const uint8_t *in, size_t ilen, areion_256_opp_t *state);

// finalize AREION-256-OPP state
//
// in
//   olimit: output buffer size.  olimit must be >= LI - LO
//           where LI = total input length passed
//                 LO = total output length already returned
//           unused if out == NULL
// out
//   out: output buffer.
//   olen:  bytes count written
// in/out
//   tag: return tag value on encryption, pass tag value on decryption
//   state: AREION-256-OPP state
bool finalize_areion_256_opp(uint8_t *out, size_t *olen, size_t olimit, uint8_t *tag, areion_256_opp_t *state);

typedef struct areion_512_opp_t areion_512_opp_t;

areion_512_opp_t *alloc_areion_512_opp();
void free_areion_512_opp(areion_512_opp_t *state);

// initialize AREION-512-OPP state
//
// in
//   enc: true if encrypt, false if decrypt
//   nonce: nonce (128 bit)
//   key: key (128 bit)
// in/out
//   state: AREION-512-OPP state
bool initialize_areion_512_opp(bool enc, const uint8_t nonce[AREION_512_OPP_NONCE_LEN], const uint8_t key[AREION_512_OPP_KEY_LEN], areion_512_opp_t *state);

// update AREION-512-OPP state
//
// in
//   in, ilen: input message
//   olimit: output buffer size.  olimit must be >= (LI & ~63) - LO
//           where LI = total input length passed includes ilen
//                 LO = total output length already returned
//           unused if out == NULL
// out
//   out: output buffer.  NULL if input message is associated data.
//   olen:  bytes count written
// in/out
//   state: AREION-512-OPP state
bool update_areion_512_opp(uint8_t *out, size_t *olen, size_t olimit, const uint8_t *in, size_t ilen, areion_512_opp_t *state);

// finalize AREION-512-OPP state
//
// in
//   olimit: output buffer size.  olimit must be >= LI - LO
//           where LI = total input length passed
//                 LO = total output length already returned
//           unused if out == NULL
// out
//   out: output buffer.
//   olen:  bytes count written
// in/out
//   tag: return tag value on encryption, pass tag value on decryption
//   state: AREION-512-OPP state
bool finalize_areion_512_opp(uint8_t *out, size_t *olen, size_t olimit, uint8_t *tag, areion_512_opp_t *state);

#endif
