/* Copyright (c) 2025 GMO Cybersecurity by Ierae, Inc. All rights reserved. */
/* This software is implemented based on the algorithms designed in the following research paper. */
/* see: https://eprint.iacr.org/2023/794 */

// Merkle-Damgård

#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include "impl-ref.h"
#include "private/areion-private.h"

/* the initial hash value for sha-256 */
static const char iv[32] = {
    0x6a, 0x09, 0xe6, 0x67,
    0xbb, 0x67, 0xae, 0x85,
    0x3c, 0x6e, 0xf3, 0x72,
    0xa5, 0x4f, 0xf5, 0x3a,
    0x51, 0x0e, 0x52, 0x7f,
    0x9b, 0x05, 0x68, 0x8c,
    0x1f, 0x83, 0xd9, 0xab,
    0x5b, 0xe0, 0xcd, 0x19,
};

static void compression(const uint8_t message[32], uint8_t output[32])
{
    areion_word_t input[4];
    areion_load_256(&input[0], message);
    areion_load_256(&input[2], output);
    areion_word_t cipher[4];
    permute_areion_512(cipher, input);
    /* xor message to get DM effect */
    cipher[0] = areion_xor(cipher[0], input[0]);
    cipher[1] = areion_xor(cipher[1], input[1]);
    cipher[2] = areion_xor(cipher[2], input[2]);
    cipher[3] = areion_xor(cipher[3], input[3]);
    *(uint64_t *)(output +  0) = areion_extract1_64(cipher[0]);
    *(uint64_t *)(output +  8) = areion_extract1_64(cipher[1]);
    *(uint64_t *)(output + 16) = areion_extract0_64(cipher[2]);
    *(uint64_t *)(output + 24) = areion_extract0_64(cipher[3]);
}

void crypto_hash_areion_md_ref(
    const uint8_t *message, size_t mlen,
    uint8_t *hash_value)
{
    uint32_t bits = mlen * 8;
    uint8_t output[32];

    memcpy(output, iv, 32);
    
    while (mlen >= 32) {
        compression(message, output);
        message += 32;
        mlen -= 32;
    }

    {
        uint8_t padding[32];
        memcpy(padding, message, mlen);
        padding[mlen] = 0x80;
        mlen++;

        if (mlen > 28) {
            // need two blocks
            memset(padding + mlen, 0, 32 - mlen);
            compression(padding, output);
            mlen = 0;
        }
        // single block padding
        memset(padding + mlen, 0, 28 - mlen);
        padding[28] = bits >> 24;
        padding[29] = bits >> 16;
        padding[30] = bits >> 8;
        padding[31] = bits;
        compression(padding, output);
    }
    memcpy(hash_value, output, 32);
}
