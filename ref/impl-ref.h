/* Copyright (c) 2025 GMO Cybersecurity by Ierae, Inc. All rights reserved. */

#ifndef AREION_IMPL_REF_H
#define AREION_IMPL_REF_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "areion.h"

void permute_areion_256_ref(areion_word_t dst[2], const areion_word_t src[2]);
void inverse_areion_256_ref(areion_word_t dst[2], const areion_word_t src[2]);
void permute_areion_512_ref(areion_word_t dst[4], const areion_word_t src[4]);
void inverse_areion_512_ref(areion_word_t dst[4], const areion_word_t src[4]);
void permute_areion_256u8_ref(uint8_t dst[32], const uint8_t src[32]);
void inverse_areion_256u8_ref(uint8_t dst[32], const uint8_t src[32]);
void permute_areion_512u8_ref(uint8_t dst[64], const uint8_t src[64]);
void inverse_areion_512u8_ref(uint8_t dst[64], const uint8_t src[64]);
void encrypt_areion_256_opp_ref(
    uint8_t *c,
    uint8_t tag[AREION_256_OPP_TAG_LEN],
    const uint8_t *h, size_t hlen,
    const uint8_t *m, size_t mlen,
    const uint8_t nonce[AREION_256_OPP_NONCE_LEN],
    const uint8_t key[AREION_256_OPP_KEY_LEN]);
int decrypt_areion_256_opp_ref(
    uint8_t *m,
    const uint8_t tag[AREION_256_OPP_TAG_LEN],
    const uint8_t *h, size_t hlen,
    const uint8_t *c, size_t clen,
    const uint8_t nonce[AREION_256_OPP_NONCE_LEN],
    const uint8_t key[AREION_256_OPP_KEY_LEN]);
void encrypt_areion_512_opp_ref(
    uint8_t *c,
    uint8_t tag[AREION_512_OPP_TAG_LEN],
    const uint8_t *h, size_t hlen,
    const uint8_t *m, size_t mlen,
    const uint8_t nonce[AREION_512_OPP_NONCE_LEN],
    const uint8_t key[AREION_512_OPP_KEY_LEN]);
int decrypt_areion_512_opp_ref(
    uint8_t *m,
    const uint8_t tag[AREION_512_OPP_TAG_LEN],
    const uint8_t *h, size_t hlen,
    const uint8_t *c, size_t clen,
    const uint8_t nonce[AREION_512_OPP_NONCE_LEN],
    const uint8_t key[AREION_512_OPP_KEY_LEN]);

typedef struct areion_256_opp_ref_t areion_256_opp_ref_t;

areion_256_opp_ref_t *alloc_areion_256_opp_ref();
void free_areion_256_opp_ref(areion_256_opp_ref_t *state);
bool initialize_areion_256_opp_ref(bool enc, const uint8_t nonce[AREION_256_OPP_NONCE_LEN], const uint8_t key[AREION_256_OPP_KEY_LEN], areion_256_opp_ref_t *state);
bool update_areion_256_opp_ref(uint8_t *out, size_t *olen, size_t olimit, const uint8_t *in, size_t ilen, areion_256_opp_ref_t *state);
bool finalize_areion_256_opp_ref(uint8_t *out, size_t *olen, size_t olimit, uint8_t *tag, areion_256_opp_ref_t *state);

typedef struct areion_512_opp_ref_t areion_512_opp_ref_t;

areion_512_opp_ref_t *alloc_areion_512_opp_ref();
void free_areion_512_opp_ref(areion_512_opp_ref_t *state);
bool initialize_areion_512_opp_ref(bool enc, const uint8_t nonce[AREION_512_OPP_NONCE_LEN], const uint8_t key[AREION_512_OPP_KEY_LEN], areion_512_opp_ref_t *state);
bool update_areion_512_opp_ref(uint8_t *out, size_t *olen, size_t olimit, const uint8_t *in, size_t ilen, areion_512_opp_ref_t *state);
bool finalize_areion_512_opp_ref(uint8_t *out, size_t *olen, size_t olimit, uint8_t *tag, areion_512_opp_ref_t *state);

void crypto_hash_areion_256_dm_ref(
    const uint8_t message[32],
    uint8_t hash_value[32]);
void crypto_hash_areion_512_dm_ref(
    const uint8_t message[64],
    uint8_t hash_value[32]);
void crypto_hash_areion_md_ref(
    const uint8_t *message, size_t mlen,
    uint8_t hash_value[CRYPTO_HASH_AREION_MD_LEN]);
#endif
