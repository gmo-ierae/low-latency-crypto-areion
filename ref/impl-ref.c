/* Copyright (c) 2025 GMO Cybersecurity by Ierae, Inc. All rights reserved. */

#include "impl-ref.h"

void permute_areion_256(areion_word_t dst[2], const areion_word_t src[2])
{
    permute_areion_256_ref(dst, src);
}
void inverse_areion_256(areion_word_t dst[2], const areion_word_t src[2])
{
    inverse_areion_256_ref(dst, src);
}
void permute_areion_512(areion_word_t dst[4], const areion_word_t src[4])
{
    permute_areion_512_ref(dst, src);
}
void inverse_areion_512(areion_word_t dst[4], const areion_word_t src[4])
{
    inverse_areion_512_ref(dst, src);
}
void permute_areion_256u8(uint8_t dst[32], const uint8_t src[32])
{
    permute_areion_256u8_ref(dst, src);
}
void inverse_areion_256u8(uint8_t dst[32], const uint8_t src[32])
{
    inverse_areion_256u8_ref(dst, src);
}
void permute_areion_512u8(uint8_t dst[64], const uint8_t src[64])
{
    permute_areion_512u8_ref(dst, src);
}
void inverse_areion_512u8(uint8_t dst[64], const uint8_t src[64])
{
    inverse_areion_512u8_ref(dst, src);
}
void encrypt_areion_256_opp(
    uint8_t *c,
    uint8_t tag[AREION_256_OPP_TAG_LEN],
    const uint8_t *h, size_t hlen,
    const uint8_t *m, size_t mlen,
    const uint8_t nonce[AREION_256_OPP_NONCE_LEN],
    const uint8_t key[AREION_256_OPP_KEY_LEN])
{
    encrypt_areion_256_opp_ref(c, tag, h, hlen, m, mlen, nonce, key);
}
int decrypt_areion_256_opp(
    uint8_t *m,
    const uint8_t tag[AREION_256_OPP_TAG_LEN],
    const uint8_t *h, size_t hlen,
    const uint8_t *c, size_t clen,
    const uint8_t nonce[AREION_256_OPP_NONCE_LEN],
    const uint8_t key[AREION_256_OPP_KEY_LEN])
{
    return decrypt_areion_256_opp_ref(m, tag, h, hlen, c, clen, nonce, key);
}
void encrypt_areion_512_opp(
    uint8_t *c,
    uint8_t tag[AREION_512_OPP_TAG_LEN],
    const uint8_t *h, size_t hlen,
    const uint8_t *m, size_t mlen,
    const uint8_t nonce[AREION_512_OPP_NONCE_LEN],
    const uint8_t key[AREION_512_OPP_KEY_LEN])
{
    encrypt_areion_512_opp_ref(c, tag, h, hlen, m, mlen, nonce, key);
}
int decrypt_areion_512_opp(
    uint8_t *m,
    const uint8_t tag[AREION_512_OPP_TAG_LEN],
    const uint8_t *h, size_t hlen,
    const uint8_t *c, size_t clen,
    const uint8_t nonce[AREION_512_OPP_NONCE_LEN],
    const uint8_t key[AREION_512_OPP_KEY_LEN])
{
    return decrypt_areion_512_opp_ref(m, tag, h, hlen, c, clen, nonce, key);
}

areion_256_opp_t *alloc_areion_256_opp()
{
    return (areion_256_opp_t *)alloc_areion_256_opp_ref();
}
void free_areion_256_opp(areion_256_opp_t *state)
{
    free_areion_256_opp_ref((areion_256_opp_ref_t *)state);
}
bool initialize_areion_256_opp(bool enc, const uint8_t nonce[AREION_256_OPP_NONCE_LEN], const uint8_t key[AREION_256_OPP_KEY_LEN], areion_256_opp_t *state)
{
    return initialize_areion_256_opp_ref(enc, nonce, key, (areion_256_opp_ref_t *)state);
}
bool update_areion_256_opp(uint8_t *out, size_t *olen, size_t olimit, const uint8_t *in, size_t ilen, areion_256_opp_t *state)
{
    return update_areion_256_opp_ref(out, olen, olimit, in, ilen, (areion_256_opp_ref_t *)state);
}
bool finalize_areion_256_opp(uint8_t *out, size_t *olen, size_t olimit, uint8_t *tag, areion_256_opp_t *state)
{
    return finalize_areion_256_opp_ref(out, olen, olimit, tag, (areion_256_opp_ref_t *)state);
}

areion_512_opp_t *alloc_areion_512_opp()
{
    return (areion_512_opp_t *)alloc_areion_512_opp_ref();
}
void free_areion_512_opp(areion_512_opp_t *state)
{
    free_areion_512_opp_ref((areion_512_opp_ref_t *)state);
}
bool initialize_areion_512_opp(bool enc, const uint8_t nonce[AREION_512_OPP_NONCE_LEN], const uint8_t key[AREION_512_OPP_KEY_LEN], areion_512_opp_t *state)
{
    return initialize_areion_512_opp_ref(enc, nonce, key, (areion_512_opp_ref_t *)state);
}
bool update_areion_512_opp(uint8_t *out, size_t *olen, size_t olimit, const uint8_t *in, size_t ilen, areion_512_opp_t *state)
{
    return update_areion_512_opp_ref(out, olen, olimit, in, ilen, (areion_512_opp_ref_t *)state);
}
bool finalize_areion_512_opp(uint8_t *out, size_t *olen, size_t olimit, uint8_t *tag, areion_512_opp_t *state)
{
    return finalize_areion_512_opp_ref(out, olen, olimit, tag, (areion_512_opp_ref_t *)state);
}

void crypto_hash_areion_256_dm(
    const uint8_t message[32],
    uint8_t hash_value[32])
{
    crypto_hash_areion_256_dm_ref(message, hash_value);
}
void crypto_hash_areion_512_dm(
    const uint8_t message[64],
    uint8_t hash_value[32])
{
    crypto_hash_areion_512_dm_ref(message, hash_value);
}
void crypto_hash_areion_md(
    const uint8_t *message, size_t mlen,
    uint8_t hash_value[CRYPTO_HASH_AREION_MD_LEN])
{
    crypto_hash_areion_md_ref(message, mlen, hash_value);
}
