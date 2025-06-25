/* Copyright (c) 2025 GMO Cybersecurity by Ierae, Inc. All rights reserved. */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include "areion.h"
#include "../ref/impl-ref.h"

static int n_fails = 0;

static void fail(const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    vprintf(fmt, va);
    va_end(va);
    n_fails++;
}

static void fill(uint8_t *dst, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        dst[i] = rand();
    }
}

static void test_opp_256(size_t len)
{
    uint8_t key[AREION_256_OPP_KEY_LEN];
    uint8_t nonce[AREION_256_OPP_NONCE_LEN];
    uint8_t h[4096];
    uint8_t in[4096];
    fill(key, sizeof key);
    fill(nonce, sizeof nonce);
    fill(h, len);
    fill(in, len);

    uint8_t expected_out[4096];
    uint8_t expected_tag[AREION_256_OPP_TAG_LEN];
    encrypt_areion_256_opp_ref(expected_out, expected_tag, h, len, in, len, nonce, key);

    uint8_t out[4096];
    uint8_t tag[AREION_256_OPP_TAG_LEN];
    encrypt_areion_256_opp(out, tag, h, len, in, len, nonce, key);
    if (memcmp(expected_out, out, len) != 0) {
        fail("test_opp_256: encrypt_areion_256_opp ciphertext not match\n");
        return;
    }
    if (memcmp(expected_tag, tag, AREION_256_OPP_TAG_LEN) != 0) {
        fail("test_opp_256: encrypt_areion_256_opp tag not match\n");
        return;
    }
    if (decrypt_areion_256_opp(out, expected_tag, h, len, expected_out, len, nonce, key) != 0) {
        fail("test_opp_256: decrypt_areion_256_opp failed\n");
        return;
    }
    if (memcmp(in, out, len) != 0) {
        fail("test_opp_256: decrypt_areion_256_opp plaintext not match\n");
        return;
    }

    for (int e = 0; e < 2; e++) {
        bool enc = e == 0;
        areion_256_opp_t *opp = alloc_areion_256_opp();
        if (!initialize_areion_256_opp(enc, nonce, key, opp)) {
            fail("test_opp_256: initialize_areion_256_opp failed\n");
            return;
        }
        if (!update_areion_256_opp(NULL, NULL, 0, h, len, opp)) {
            fail("test_opp_256: update_areion_256_opp failed\n");
            return;
        }
        size_t total_len = 0;
        size_t olen;
        if (!update_areion_256_opp(out, &olen, len, enc ? in : expected_out, len, opp)) {
            fail("test_opp_256: update_areion_256_opp failed\n");
            return;
        }
        total_len += olen;
        if (!finalize_areion_256_opp(out + total_len, &olen, len - total_len, enc ? tag : expected_tag, opp)) {
            fail("test_opp_256: finalize_areion_256_opp failed\n");
            return;
        }
        total_len += olen;
        if (total_len != len) {
            fail("test_opp_256: finalize_areion_256_opp len not match\n");
            return;
        }
        if (enc) {
            if (memcmp(expected_out, out, len) != 0) {
                fail("test_opp_256: finalize_areion_256_opp ciphertext not match\n");
                return;
            }
            if (memcmp(expected_tag, tag, AREION_256_OPP_TAG_LEN) != 0) {
                fail("test_opp_256: finalize_areion_256_opp tag not match\n");
                return;
            }
        } else {
            if (memcmp(in, out, len) != 0) {
                fail("test_opp_256: finalize_areion_256_opp plaintext not match\n");
                return;
            }
        }
    }
}

static void test_opp_512(size_t len)
{
    uint8_t key[AREION_512_OPP_KEY_LEN];
    uint8_t nonce[AREION_512_OPP_NONCE_LEN];
    uint8_t h[4096];
    uint8_t in[4096];
    fill(key, sizeof key);
    fill(nonce, sizeof nonce);
    fill(h, len);
    fill(in, len);

    uint8_t expected_out[4096];
    uint8_t expected_tag[AREION_512_OPP_TAG_LEN];
    encrypt_areion_512_opp_ref(expected_out, expected_tag, h, len, in, len, nonce, key);

    uint8_t out[4096];
    uint8_t tag[AREION_512_OPP_TAG_LEN];
    encrypt_areion_512_opp(out, tag, h, len, in, len, nonce, key);
    if (memcmp(expected_out, out, len) != 0) {
        fail("test_opp_512: encrypt_areion_512_opp ciphertext not match\n");
        return;
    }
    if (memcmp(expected_tag, tag, AREION_512_OPP_TAG_LEN) != 0) {
        fail("test_opp_512: encrypt_areion_512_opp tag not match\n");
        return;
    }
    if (decrypt_areion_512_opp(out, expected_tag, h, len, expected_out, len, nonce, key) != 0) {
        fail("test_opp_512: decrypt_areion_512_opp failed\n");
        return;
    }
    if (memcmp(in, out, len) != 0) {
        fail("test_opp_512: decrypt_areion_512_opp plaintext not match\n");
        return;
    }

    for (int e = 0; e < 2; e++) {
        bool enc = e == 0;
        areion_512_opp_t *opp = alloc_areion_512_opp();
        if (!initialize_areion_512_opp(enc, nonce, key, opp)) {
            fail("test_opp_512: initialize_areion_512_opp failed\n");
            return;
        }
        if (!update_areion_512_opp(NULL, NULL, 0, h, len, opp)) {
            fail("test_opp_512: update_areion_512_opp failed\n");
            return;
        }
        size_t total_len = 0;
        size_t olen;
        if (!update_areion_512_opp(out, &olen, len, enc ? in : expected_out, len, opp)) {
            fail("test_opp_512: update_areion_512_opp failed\n");
            return;
        }
        total_len += olen;
        if (!finalize_areion_512_opp(out + total_len, &olen, len - total_len, enc ? tag : expected_tag, opp)) {
            fail("test_opp_512: finalize_areion_512_opp failed\n");
            return;
        }
        total_len += olen;
        if (total_len != len) {
            fail("test_opp_512: finalize_areion_512_opp len not match\n");
            return;
        }
        if (enc) {
            if (memcmp(expected_out, out, len) != 0) {
                fail("test_opp_512: finalize_areion_512_opp ciphertext not match\n");
                return;
            }
            if (memcmp(expected_tag, tag, AREION_512_OPP_TAG_LEN) != 0) {
                fail("test_opp_512: finalize_areion_512_opp tag not match\n");
                return;
            }
        } else {
            if (memcmp(in, out, len) != 0) {
                fail("test_opp_512: finalize_areion_512_opp plaintext not match\n");
                return;
            }
        }
    }
}

int main()
{
    srand(time(NULL));
    for (size_t i = 0; i < 256; i++) {
        test_opp_256(i);
        test_opp_256(2048 + i);
        test_opp_512(i);
        test_opp_512(2048 + i);
    }

    if (n_fails == 0) {
        printf("all test passed\n");
        return 0;
    } else {
        printf("%d tests failed\n", n_fails);
        return 1;
    }
}
