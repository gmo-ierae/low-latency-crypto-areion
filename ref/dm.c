/* Copyright (c) 2025 GMO Cybersecurity by Ierae, Inc. All rights reserved. */
/* This software is implemented based on the algorithms designed in the following research paper. */
/* see: https://eprint.iacr.org/2023/794 */

// Davies-Meyer
#include <stdint.h>
#include "impl-ref.h"
#include "private/areion-private.h"

void crypto_hash_areion_256_dm_ref(
    const uint8_t message[32],
    uint8_t hash_value[32])
{
    areion_word_t input[2];
    areion_load_256(input, message);
    areion_word_t cipher[2];
    permute_areion_256(cipher, input);
    /* xor message to get DM effect */
    cipher[0] = areion_xor(cipher[0], input[0]);
    cipher[1] = areion_xor(cipher[1], input[1]);
    areion_store_256(hash_value, cipher);
}

void crypto_hash_areion_512_dm_ref(
    const uint8_t message[64],
    uint8_t hash_value[32])
{
    areion_word_t input[4];
    areion_load_512(input, message);
    areion_word_t cipher[4];
    permute_areion_512(cipher, input);
    /* xor message to get DM effect */
    cipher[0] = areion_xor(cipher[0], input[0]);
    cipher[1] = areion_xor(cipher[1], input[1]);
    cipher[2] = areion_xor(cipher[2], input[2]);
    cipher[3] = areion_xor(cipher[3], input[3]);
    *(uint64_t *)(hash_value +  0) = areion_extract1_64(cipher[0]);
    *(uint64_t *)(hash_value +  8) = areion_extract1_64(cipher[1]);
    *(uint64_t *)(hash_value + 16) = areion_extract0_64(cipher[2]);
    *(uint64_t *)(hash_value + 24) = areion_extract0_64(cipher[3]);
}

