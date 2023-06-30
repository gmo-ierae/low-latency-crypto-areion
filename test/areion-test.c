/* Copyright (c) 2023 GMO Cybersecurity by Ierae, Inc. All rights reserved. */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include "areion.h"

static int n_fails = 0;

static void fail(const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    vprintf(fmt, va);
    va_end(va);
    n_fails++;
}

static void test_256(const char *name, const uint8_t in[32], const uint8_t out[32])
{
    uint8_t x[32];
    permute_areion_256u8(x, in);
    if (memcmp(x, out, 32) != 0) {
        fail("%s: permute failed\n", name);
        return;
    }
    inverse_areion_256u8(x, x);
    if (memcmp(x, in, 32) != 0) {
        fail("%s: inverse failed\n", name);
        return;
    }
    printf("%s: passed\n", name);
}

static void test_512(const char *name, const uint8_t in[64], const uint8_t out[64])
{
    uint8_t x[64];
    permute_areion_512u8(x, in);
    if (memcmp(x, out, 64) != 0) {
        fail("%s: permute failed\n", name);
        return;
    }
    inverse_areion_512u8(x, x);
    if (memcmp(x, in, 64) != 0) {
        fail("%s: inverse failed\n", name);
        return;
    }
    printf("%s: passed\n", name);
}

static void test_256_opp(const char *name,
    const uint8_t key[AREION_256_OPP_KEY_LEN],
    const uint8_t nonce[AREION_256_OPP_NONCE_LEN],
    const uint8_t *h, size_t hlen,
    const uint8_t *m, const uint8_t *c, size_t len,
    const uint8_t tag[AREION_256_OPP_TAG_LEN])
{
    uint8_t cipher[256];
    uint8_t cipher_tag[AREION_256_OPP_TAG_LEN];
    encrypt_areion_256_opp(cipher, cipher_tag, h, hlen, m, len, nonce, key);
    if (memcmp(cipher, c, len) != 0) {
        fail("%s: ciphertext compare failed\n", name);
        return;
    }
    if (memcmp(cipher_tag, tag, AREION_256_OPP_TAG_LEN) != 0) {
        fail("%s: tag compare failed\n", name);
        return;
    }
    uint8_t plain[256];
    int ret = decrypt_areion_256_opp(plain, tag, h, hlen, c, len, nonce, key);
    if (ret != 0) {
        fail("%s: decrypt failed\n", name);
        return;
    }
    if (memcmp(plain, m, len) != 0) {
        fail("%s: plaintext compare failed\n", name);
        return;
    }
    printf("%s: passed\n", name);
}

static void test_256_opp_stream(const char *name,
    const uint8_t key[16], const uint8_t nonce[16],
    const uint8_t *h, size_t hlen,
    const uint8_t *m, const uint8_t *c, size_t mlen,
    const uint8_t tag[AREION_256_OPP_TAG_LEN])
{
    areion_256_opp_t *state;
    size_t len;
    uint8_t cipher[256];
    size_t cipher_len;
    uint8_t cipher_tag[16];

    state = alloc_areion_256_opp();

    initialize_areion_256_opp(true, nonce, key, state);
    if (!update_areion_256_opp(NULL, NULL, 0, h, hlen, state)) {
        fail("%s: ENC update_areion_256_opp failed\n", name);
        return;
    }
    cipher_len = 0;
    if (!update_areion_256_opp(cipher + cipher_len, &len, sizeof cipher, m, mlen, state)) {
        fail("%s: ENC update_areion_256_opp AD failed\n", name);
        return;
    }
    cipher_len += len;
    if (!finalize_areion_256_opp(cipher + cipher_len, &len, sizeof cipher - cipher_len, cipher_tag, state)) {
        fail("%s: ENC finalize_areion_256_opp failed\n", name);
        return;
    }
    cipher_len += len;
    if (mlen != cipher_len) {
        fail("%s: cipher len failed\n", name);
        return;
    }
    if (memcmp(cipher, c, mlen) != 0) {
        fail("%s: ciphertext compare failed\n", name);
        return;
    }
    if (memcmp(cipher_tag, tag, AREION_256_OPP_TAG_LEN) != 0) {
        fail("%s: tag compare failed\n", name);
        return;
    }

    uint8_t plain[256];
    size_t plain_len;
    initialize_areion_256_opp(false, nonce, key, state);
    if (!update_areion_256_opp(NULL, NULL, 0, h, hlen, state)) {
        fail("%s: DEC update_areion_256_opp AD failed\n", name);
        return;
    }
    plain_len = 0;
    if (!update_areion_256_opp(plain, &len, sizeof plain, c, mlen, state)) {
        fail("%s: DEC update_areion_256_opp failed\n", name);
        return;
    }
    plain_len += len;
    if (!finalize_areion_256_opp(plain + plain_len, &len, sizeof plain - plain_len, (uint8_t *)tag, state)) {
        fail("%s: DEC finalize_areion_256_opp failed\n", name);
        return;
    }
    plain_len += len;

    if (plain_len != mlen) {
        fail("%s: plain len failed\n", name);
        return;
    }
    if (memcmp(plain, m, mlen) != 0) {
        fail("%s: plaintext compare failed\n", name);
        return;
    }
    free_areion_256_opp(state);
    printf("%s: passed\n", name);
}

static void test_512_opp(const char *name,
    const uint8_t key[AREION_512_OPP_KEY_LEN],
    const uint8_t nonce[AREION_512_OPP_NONCE_LEN],
    const uint8_t *h, size_t hlen,
    const uint8_t *m, const uint8_t *c, size_t len,
    const uint8_t tag[AREION_512_OPP_TAG_LEN])
{
    uint8_t cipher[256];
    uint8_t cipher_tag[AREION_512_OPP_TAG_LEN];
    encrypt_areion_512_opp(cipher, cipher_tag, h, hlen, m, len, nonce, key);
    if (memcmp(cipher, c, len) != 0) {
        fail("%s: ciphertext compare failed\n", name);
        return;
    }
    if (memcmp(cipher_tag, tag, AREION_512_OPP_TAG_LEN) != 0) {
        fail("%s: tag compare failed\n", name);
        return;
    }
    uint8_t plain[256];
    int ret = decrypt_areion_512_opp(plain, tag, h, hlen, c, len, nonce, key);
    if (ret != 0) {
        fail("%s: decrypt failed\n", name);
        return;
    }
    if (memcmp(plain, m, len) != 0) {
        fail("%s: plaintext compare failed\n", name);
        return;
    }
    printf("%s: passed\n", name);
}

static void test_512_opp_stream(const char *name,
    const uint8_t key[16], const uint8_t nonce[16],
    const uint8_t *h, size_t hlen,
    const uint8_t *m, const uint8_t *c, size_t mlen,
    const uint8_t tag[AREION_512_OPP_TAG_LEN])
{
    areion_512_opp_t *state;
    size_t len;
    uint8_t cipher[256];
    size_t cipher_len;
    uint8_t cipher_tag[16];

    state = alloc_areion_512_opp();

    initialize_areion_512_opp(true, nonce, key, state);
    if (!update_areion_512_opp(NULL, NULL, 0, h, hlen, state)) {
        fail("%s: ENC update_areion_512_opp failed\n", name);
        return;
    }
    cipher_len = 0;
    if (!update_areion_512_opp(cipher + cipher_len, &len, sizeof cipher, m, mlen, state)) {
        fail("%s: ENC update_areion_512_opp AD failed\n", name);
        return;
    }
    cipher_len += len;
    if (!finalize_areion_512_opp(cipher + cipher_len, &len, sizeof cipher - cipher_len, cipher_tag, state)) {
        fail("%s: ENC finalize_areion_512_opp failed\n", name);
        return;
    }
    cipher_len += len;
    if (mlen != cipher_len) {
        fail("%s: cipher len failed\n", name);
        return;
    }
    if (memcmp(cipher, c, mlen) != 0) {
        fail("%s: ciphertext compare failed\n", name);
        return;
    }
    if (memcmp(cipher_tag, tag, AREION_512_OPP_TAG_LEN) != 0) {
        fail("%s: tag compare failed\n", name);
        return;
    }

    uint8_t plain[256];
    size_t plain_len;
    initialize_areion_512_opp(false, nonce, key, state);
    if (!update_areion_512_opp(NULL, NULL, 0, h, hlen, state)) {
        fail("%s: DEC update_areion_512_opp AD failed\n", name);
        return;
    }
    plain_len = 0;
    if (!update_areion_512_opp(plain, &len, sizeof plain, c, mlen, state)) {
        fail("%s: DEC update_areion_512_opp failed\n", name);
        return;
    }
    plain_len += len;
    if (!finalize_areion_512_opp(plain + plain_len, &len, sizeof plain - plain_len, (uint8_t *)tag, state)) {
        fail("%s: DEC finalize_areion_512_opp failed\n", name);
        return;
    }
    plain_len += len;

    if (plain_len != mlen) {
        fail("%s: plain len failed\n", name);
        return;
    }
    if (memcmp(plain, m, mlen) != 0) {
        fail("%s: plaintext compare failed\n", name);
        return;
    }
    free_areion_512_opp(state);
    printf("%s: passed\n", name);
}

static void test_primitives()
{
    {
        uint8_t in[32] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };
        uint8_t out[32] = {
            0xe5, 0xa7, 0x66, 0x63, 0x82, 0x50, 0x14, 0x24,
            0x68, 0xdc, 0x9d, 0x76, 0x65, 0xdd, 0x36, 0x9f,
            0x8f, 0x79, 0x99, 0x8b, 0x7a, 0xa0, 0x92, 0x90,
            0x6f, 0xe5, 0x1b, 0xfd, 0xeb, 0xfa, 0xc9, 0xc1,
        };
        test_256("areion 256 test vector #1", in, out);
    }

    {
        uint8_t in[32] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        };
        uint8_t out[32] = {
            0x73, 0x53, 0xec, 0x51, 0xd4, 0x9f, 0xad, 0x89,
            0xee, 0xcb, 0x5b, 0xef, 0x1e, 0xa0, 0xe4, 0x76,
            0xed, 0x6c, 0xdc, 0xdd, 0xaf, 0x34, 0x62, 0x0d,
            0x01, 0x3d, 0xcc, 0xf2, 0xa2, 0x26, 0xf4, 0x57,
        };
        test_256("areion 256 test vector #2", in, out);
    }

    {
        uint8_t in[64] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };
        uint8_t out[64] = {
            0x5f, 0xee, 0xf7, 0x7c, 0xbb, 0xe8, 0x4c, 0x79,
            0x58, 0x08, 0x94, 0x59, 0xf4, 0x54, 0xe9, 0x6f,
            0xbf, 0x21, 0xfa, 0xb8, 0x35, 0x65, 0xcc, 0xaf,
            0x91, 0x6b, 0xcf, 0x9c, 0xfb, 0x63, 0xd2, 0x5b,
            0xa0, 0x26, 0x42, 0xfc, 0xc1, 0x75, 0x12, 0x36,
            0x40, 0xd6, 0xa2, 0x18, 0x3b, 0xa6, 0x82, 0xb2,
            0x0b, 0x72, 0x3a, 0xfc, 0x66, 0x68, 0xff, 0xf3,
            0xde, 0xc4, 0x7c, 0x17, 0x61, 0x27, 0xb9, 0x84,
        };
        test_512("areion 512 test vector #1", in, out);
    }

    {
        uint8_t in[64] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        };
        uint8_t out[64] = {
            0xa6, 0x09, 0x5f, 0xe0, 0x57, 0xd2, 0x83, 0x80,
            0xba, 0xd2, 0x5c, 0x28, 0x12, 0xb2, 0x30, 0xf6,
            0x6f, 0x07, 0xb0, 0x09, 0xa3, 0x04, 0x98, 0x5a,
            0xf4, 0x37, 0xbb, 0x60, 0x8a, 0x4c, 0xb8, 0x31,
            0x39, 0x2a, 0x6f, 0x2f, 0x48, 0xe4, 0x25, 0xef,
            0x24, 0x11, 0x96, 0x21, 0x67, 0x2e, 0x37, 0xc4,
            0xf1, 0x9b, 0x94, 0xe0, 0xe4, 0xea, 0xed, 0xaf,
            0xb9, 0xf4, 0xeb, 0x12, 0x6a, 0x6d, 0x8a, 0xbb,
        };
        test_512("areion 512 test vector #2", in, out);
    }
}

static void test_aead()
{
    {
        uint8_t key[AREION_256_OPP_KEY_LEN] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        };
        uint8_t nonce[AREION_256_OPP_NONCE_LEN] = {
            0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80,
            0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00,
        };
        uint8_t h[16] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        };
        uint8_t in[] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        };
        uint8_t out[] = {
            0x44, 0xB8, 0x22, 0xB5, 0xA4, 0x0F, 0x6A, 0xD8,
            0x5C, 0xF7, 0xF6, 0x97, 0xFA, 0x1F, 0x03, 0x4B,
            0x03, 0x08, 0x52, 0xA4, 0x07, 0xB7, 0x5C, 0x66,
            0x3B, 0x88, 0x4B, 0xA7, 0xE8, 0x4C, 0xC5, 0x7B,
        };
        uint8_t tag[AREION_256_OPP_TAG_LEN] = {
            0xAD, 0xC6, 0x22, 0x43, 0x73, 0xBE, 0x80, 0x56,
            0x72, 0xE7, 0xD3, 0x32, 0x58, 0x6D, 0x96, 0xE0,
        };
        test_256_opp("areion 256 OPP test vector #1", key, nonce, h, sizeof h, in, out, sizeof in, tag);
        test_256_opp_stream("areion 256 OPP stream test vector #1", key, nonce, h, sizeof h, in, out, sizeof in, tag);
    }
    {
        uint8_t key[AREION_512_OPP_KEY_LEN] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        };
        uint8_t nonce[AREION_512_OPP_NONCE_LEN] = {
            0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80,
            0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00,
        };
        uint8_t h[16] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        };
        uint8_t in[] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        };
        uint8_t out[] = {
            0x6B, 0x61, 0x94, 0xEA, 0xF2, 0x9F, 0x1A, 0x72,
            0x81, 0x5E, 0xF5, 0xAC, 0xBD, 0x4C, 0xFD, 0xE8,
            0x8A, 0x22, 0xEA, 0xF9, 0x6C, 0x67, 0x86, 0x86,
            0xAD, 0x44, 0x68, 0xDB, 0xD7, 0x64, 0x58, 0xCC,
            0x83, 0x70, 0x02, 0xE4, 0x0A, 0xCE, 0xED, 0x5F,
            0xF2, 0x23, 0xA6, 0xC5, 0x6A, 0xF0, 0xAA, 0x20,
            0x7D, 0x55, 0x18, 0x31, 0x79, 0x59, 0xE4, 0x8B,
            0x3A, 0x55, 0x62, 0x32, 0xB3, 0x64, 0x2C, 0x38,
        };
        uint8_t tag[AREION_512_OPP_TAG_LEN] = {
            0xD0, 0x42, 0x4D, 0xA9, 0xA5, 0x7A, 0x75, 0xFE,
            0x95, 0xD7, 0xFE, 0xDE, 0xBC, 0xF3, 0x7D, 0x23,
        };
        test_512_opp("areion 512 OPP test vector #1", key, nonce, h, sizeof h, in, out, sizeof in, tag);
        test_512_opp_stream("areion 512 OPP stream test vector #1", key, nonce, h, sizeof h, in, out, sizeof in, tag);
    }
}

int main()
{
    test_primitives();
    test_aead();

    if (n_fails == 0) {
        printf("all test passed\n");
        return 0;
    } else {
        printf("%d tests failed\n", n_fails);
        return 1;
    }
}
