/* Copyright (c) 2025 GMO Cybersecurity by Ierae, Inc. All rights reserved. */

#include "../ref/impl-ref.h"

void permute_areion_256(__m128i dst[2], const __m128i src[2])
{
    permute_areion_256_ref(dst, src);
}
void inverse_areion_256(__m128i dst[2], const __m128i src[2])
{
    inverse_areion_256_ref(dst, src);
}
void permute_areion_512(__m128i dst[4], const __m128i src[4])
{
    permute_areion_512_ref(dst, src);
}
void inverse_areion_512(__m128i dst[4], const __m128i src[4])
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
