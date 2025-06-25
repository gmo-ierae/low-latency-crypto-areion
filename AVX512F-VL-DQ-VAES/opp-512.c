/*
    OPP - MEM AEAD source code package

    :copyright: (c) 2015 by Philipp Jovanovic and Samuel Neves
    :copyright: (c) 2025 GMO Cybersecurity by Ierae, Inc.
    :license: Creative Commons CC0 1.0
*/

/* This software is updated based on the algorithms designed in the following research paper. */
/* see: https://eprint.iacr.org/2023/794 */

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "areion.h"

typedef uint64_t opp_word_t;

typedef struct
{
    opp_word_t S[8];
} opp_state_t;

#define OPP_W 64           /* word size */
#define OPP_T (OPP_W *  2) /* tag size */
#define OPP_N (OPP_W *  2) /* nonce size */
#define OPP_K (OPP_W *  2) /* key size */
#define OPP_B (OPP_W *  8) /* permutation width */

#if AREION_512_OPP_TAG_LEN * 8 != OPP_T
#error "AREION_512_OPP_TAG_LEN * 8 != OPP_T"
#endif
#if AREION_512_OPP_NONCE_LEN * 8 != OPP_K
#error "AREION_512_OPP_NONCE_LEN * 8 != OPP_N"
#endif
#if AREION_512_OPP_KEY_LEN * 8 != OPP_K
#error "AREION_512_OPP_KEY_LEN * 8 != OPP_K"
#endif

#define BITS(x) (sizeof(x) * CHAR_BIT)
#define BYTES(x) (((x) + 7) / 8)
#define WORDS(x) (((x) + (OPP_W-1)) / OPP_W)

static inline opp_state_t load_state(const void *in)
{
    return *(opp_state_t *)in;
}

static inline void store_state(void *out, const opp_state_t *s)
{
    *(opp_state_t *)out = *s;
}

static inline opp_state_t zero_state()
{
    return (opp_state_t) { { 0, 0, 0, 0, 0, 0, 0, 0 } };
}

static inline opp_state_t xor_state(opp_state_t x, opp_state_t y)
{
    opp_state_t v;
    for (int i = 0; i < 8; i++) {
        v.S[i] = x.S[i] ^ y.S[i];
    }
    return v;
}

static inline opp_word_t rotl(opp_word_t x, int c)
{
    return (x << c) | (x >> (BITS(x) - c));
}

static inline void opp_permute(opp_state_t *state)
{
    permute_areion_512u8((uint8_t *)state->S, (uint8_t *)state->S);
}

static inline void opp_permute_inverse(opp_state_t *state)
{
    inverse_areion_512u8((uint8_t *)state->S, (uint8_t *)state->S);
}

static inline opp_state_t opp_pad(const uint8_t *in, const size_t inlen)
{
    uint8_t block[BYTES(OPP_B)];
    for (size_t i = 0; i < BYTES(OPP_B); i++) {
        if (i < inlen) {
            block[i] = in[i];
        } else if (i == inlen) {
            block[i] = 0x01;
        } else {
            block[i] = 0;
        }
    }
    return load_state(block);
}

static inline void store_state_trunc(uint8_t *out, size_t outlen, const opp_state_t *s)
{
    uint8_t block[BYTES(OPP_B)];
    store_state(block, s);
    memcpy(out, block, outlen);
}

static inline opp_state_t opp_init_mask(const unsigned char * k, const unsigned char * n)
{
    uint8_t block[BYTES(OPP_B)];
    memcpy(&block[0], n, 16);
    memset(&block[16], 0, 32);
    memcpy(&block[48], k, 16);
    opp_state_t mask = load_state(block);
    /* apply permutation */
    opp_permute(&mask);
    return mask;
}

/* 
  b = 512, w = 64, n = 8 
  Ref. Table 1 in [Granger et al., EUROCRYPT'16]
*/
static inline opp_state_t opp_phi(opp_state_t x)
{
    opp_state_t s;

    s.S[0] = x.S[1];
    s.S[1] = x.S[2];
    s.S[2] = x.S[3];
    s.S[3] = x.S[4];
    s.S[4] = x.S[5];
    s.S[5] = x.S[6];
    s.S[6] = x.S[7];
    s.S[7] = rotl(x.S[0], 29) ^ (x.S[1] << 9);

    return s;
}

typedef struct __attribute__((aligned(64))) {
    opp_state_t state[4];
    opp_state_t mask;
} opp_memory_t;

/* alpha(x) = phi(x) */
static inline opp_state_t opp_alpha(opp_state_t x)
{
    return opp_phi(x);
}

/* beta(x) = phi(x) ^ x */
static inline opp_state_t opp_beta(opp_state_t x)
{
    opp_state_t y = opp_phi(x);
    return xor_state(y, x);
}

/* gamma(x) = phi^2(x) ^ phi(x) ^ x */
static inline opp_state_t opp_gamma(opp_state_t x)
{
    opp_state_t y = opp_phi(x);
    opp_state_t z = opp_phi(y);
    return xor_state(z, xor_state(y, x));
}

static inline opp_state_t opp_mem(opp_state_t x, opp_state_t m)
{
    opp_state_t block = xor_state(x, m);
    opp_permute(&block);
    return xor_state(block, m);
}

static inline opp_state_t opp_mem_inverse(opp_state_t x, opp_state_t m)
{
    opp_state_t block = xor_state(x, m);
    opp_permute_inverse(&block);
    return xor_state(block, m);
}

static inline void opp_absorb_block(opp_memory_t *m, const uint8_t *in)
{
    opp_state_t inb = load_state(in);
    opp_state_t outb = opp_mem(inb, m->mask);
    m->state[0] = xor_state(m->state[0], outb);
    m->mask = opp_alpha(m->mask);
}

static inline void opp_absorb_lastblock(opp_memory_t *m, const uint8_t * in, size_t inlen)
{
    m->mask = opp_beta(m->mask);
    opp_state_t inb = opp_pad(in, inlen);
    opp_state_t outb = opp_mem(inb, m->mask);
    m->state[0] = xor_state(m->state[0], outb);
}

static inline void opp_encrypt_block(opp_memory_t *m, uint8_t * out, const uint8_t * in)
{
    opp_state_t inb = load_state(in);
    opp_state_t outb = opp_mem(inb, m->mask);
    store_state(out, &outb);
    m->state[0] = xor_state(m->state[0], inb);
    m->mask = opp_alpha(m->mask);
}

static inline void opp_encrypt_lastblock(opp_memory_t *m, uint8_t * out, const uint8_t * in, size_t inlen)
{
    m->mask = opp_beta(m->mask);
    opp_state_t inb = opp_pad(in, inlen);
    opp_state_t block = opp_mem(zero_state(), m->mask);
    opp_state_t outb = xor_state(block, inb);
    store_state_trunc(out, inlen, &outb);
    m->state[0] = xor_state(m->state[0], inb);
}

static inline void opp_decrypt_block(opp_memory_t *m, uint8_t * out, const uint8_t * in)
{
    opp_state_t inb = load_state(in);
    opp_state_t outb = opp_mem_inverse(inb, m->mask);
    store_state(out, &outb);
    m->state[0] = xor_state(m->state[0], outb);
    m->mask = opp_alpha(m->mask);
}

static inline void opp_decrypt_lastblock(opp_memory_t *m, uint8_t * out, const uint8_t * in, size_t inlen)
{
    m->mask = opp_beta(m->mask);
    opp_state_t inb = opp_pad(in, inlen);
    opp_state_t block = opp_mem(zero_state(), m->mask);
    opp_state_t outb = xor_state(block, inb);
    store_state_trunc(out, inlen, &outb);
    opp_state_t plainb = opp_pad(out, inlen);
    m->state[0] = xor_state(m->state[0], plainb);
}

size_t opp_512_absorb_data_asm(opp_memory_t *m, void *dummy, const unsigned char *in, size_t inlen);
size_t opp_512_encrypt_data_asm(opp_memory_t *m, unsigned char *out, const unsigned char *in, size_t inlen);
size_t opp_512_decrypt_data_asm(opp_memory_t *m, unsigned char *out, const unsigned char *in, size_t inlen);

/* low-level interface functions */
static size_t opp_absorb_data(opp_memory_t *m, const unsigned char * in, size_t inlen, bool finalize)
{
    size_t n = opp_512_absorb_data_asm(m, 0, in, inlen);
    if (finalize && inlen - n > 0)
    {
        opp_absorb_lastblock(m, in + n, inlen - n);
        n += inlen;
    }
    return n;
}

static size_t opp_encrypt_data(opp_memory_t *m, unsigned char * out, const unsigned char * in, size_t inlen, bool finalize)
{
    size_t n = opp_512_encrypt_data_asm(m, out, in, inlen);
    if (finalize && inlen - n > 0)
    {
        opp_encrypt_lastblock(m, out + n, in + n, inlen - n);
        n += inlen;
    }
    return n;
}

static size_t opp_decrypt_data(opp_memory_t *m, unsigned char * out, const unsigned char * in, size_t inlen, bool finalize)
{
    size_t n = opp_512_decrypt_data_asm(m, out, in, inlen);
    if (finalize && inlen - n > 0)
    {
        opp_decrypt_lastblock(m, out + n, in + n, inlen - n);
        n += inlen;
    }
    return n;
}

static void opp_finalise(opp_memory_t *ma, opp_memory_t *me, unsigned char *tag)
{
    opp_state_t sa = xor_state(ma->state[0], xor_state(ma->state[1], xor_state(ma->state[2], ma->state[3])));
    opp_state_t se = xor_state(me->state[0], xor_state(me->state[1], xor_state(me->state[2], me->state[3])));
    opp_state_t m = opp_beta(opp_beta(me->mask));
    opp_state_t block = opp_mem(se, m);
    opp_state_t outb = xor_state(sa, block);
    store_state_trunc(tag, BYTES(OPP_T), &outb);
}

static int opp_verify_tag(const unsigned char * tag1, const unsigned char * tag2)
{
    unsigned acc = 0;
    size_t i;

    for(i = 0; i < BYTES(OPP_T); ++i)
    {
        acc |= tag1[i] ^ tag2[i];
    }
    return (((acc - 1) >> 8) & 1) - 1;
}


/* high level interface functions */
void encrypt_areion_512_opp(
    uint8_t *c,
    uint8_t tag[AREION_512_OPP_TAG_LEN],
    const uint8_t *h, size_t hlen,
    const uint8_t *m, size_t mlen,
    const uint8_t nonce[AREION_512_OPP_NONCE_LEN],
    const uint8_t key[AREION_512_OPP_KEY_LEN])
{
    /* init checksums and masks */
    opp_memory_t ma;
    opp_memory_t me;
    for (int i = 0; i < 4; i++) {
        ma.state[i] = zero_state();
        me.state[i] = zero_state();
    }
    ma.mask = opp_init_mask(key, nonce);
    me.mask = opp_gamma(ma.mask);

    /* absorb header */
    opp_absorb_data(&ma, h, hlen, true);

    /* encrypt message */
    opp_encrypt_data(&me, c, m, mlen, true);

    /* finalise and extract tag */
    opp_finalise(&ma, &me, tag);
}

int decrypt_areion_512_opp(
    uint8_t *m,
    const uint8_t tag[AREION_512_OPP_TAG_LEN],
    const uint8_t *h, size_t hlen,
    const uint8_t *c, size_t clen,
    const uint8_t nonce[AREION_512_OPP_NONCE_LEN],
    const uint8_t key[AREION_512_OPP_KEY_LEN])
{
    /* init checksums and masks */
    opp_memory_t ma;
    opp_memory_t me;
    for (int i = 0; i < 4; i++) {
        ma.state[i] = zero_state();
        me.state[i] = zero_state();
    }
    ma.mask = opp_init_mask(key, nonce);
    me.mask = opp_gamma(ma.mask);

    /* absorb header */
    opp_absorb_data(&ma, h, hlen, true);

    /* decrypt message */
    opp_decrypt_data(&me, m, c, clen, true);

    /* finalise and extract tag */
    unsigned char cipher_tag[BYTES(OPP_T)];
    opp_finalise(&ma, &me, cipher_tag);

    /* verify tag */
    int result = opp_verify_tag(tag, cipher_tag);

    return result;
}

struct areion_512_opp_t
{
    opp_memory_t Ma;
    opp_memory_t Me;
    uint8_t ad_buf[64];
    uint8_t buf[64];
    int ad_partial_len;
    int partial_len;
    bool enc;
};

areion_512_opp_t *alloc_areion_512_opp()
{
    return aligned_alloc(64, sizeof (areion_512_opp_t));
}

void free_areion_512_opp(areion_512_opp_t *state)
{
    free(state);
}

bool initialize_areion_512_opp(bool enc, const uint8_t *n, const uint8_t *k, areion_512_opp_t *state)
{
    state->enc = enc;
    state->ad_partial_len = 0;
    state->partial_len = 0;
    for (int i = 0; i < 4; i++) {
        state->Ma.state[i] = zero_state();
        state->Me.state[i] = zero_state();
    }
    state->Ma.mask = opp_init_mask(k, n);
    state->Me.mask = opp_gamma(state->Ma.mask);
    return true;
}

bool update_areion_512_opp(uint8_t *out, size_t *olen, size_t olimit, const uint8_t *in, size_t ilen, areion_512_opp_t *state)
{
    if (!out) {
        // AD
        if (state->ad_partial_len > 0) {
            while (ilen > 0 && state->ad_partial_len < BYTES(OPP_B)) {
                state->ad_buf[state->ad_partial_len] = *in;
                state->ad_partial_len++;
                in++;
                ilen--;
            }
            if (state->ad_partial_len == BYTES(OPP_B)) {
                opp_absorb_data(&state->Ma, state->ad_buf, BYTES(OPP_B), false);
                state->ad_partial_len = 0;
            }
        }
        size_t n = opp_absorb_data(&state->Ma, in, ilen, false);
        in += n;
        ilen -= n;
        while (ilen > 0) {
            state->ad_buf[state->ad_partial_len] = *in;
            state->ad_partial_len++;
            in++;
            ilen--;
        }
    } else {
        // plain/cipher text
        if (olimit < (state->partial_len + ilen) / BYTES(OPP_B) * BYTES(OPP_B)) {
            return false;
        }
        *olen = 0;
        if (state->partial_len > 0) {
            while (ilen > 0 && state->partial_len < BYTES(OPP_B)) {
                state->buf[state->partial_len] = *in;
                state->partial_len++;
                in++;
                ilen--;
            }
            if (state->partial_len == BYTES(OPP_B)) {
                if (state->enc) {
                    opp_encrypt_data(&state->Me, out, state->buf, BYTES(OPP_B), false);
                } else {
                    opp_decrypt_data(&state->Me, out, state->buf, BYTES(OPP_B), false);
                }
                state->partial_len = 0;
                out += BYTES(OPP_B);
                *olen += BYTES(OPP_B);
            }
        }
        size_t n = state->enc
            ? opp_encrypt_data(&state->Me, out, in, ilen, false)
            : opp_decrypt_data(&state->Me, out, in, ilen, false);

        in += n;
        ilen -= n;
        out += n;
        *olen += n;
        while (ilen > 0) {
            state->buf[state->partial_len] = *in;
            state->partial_len++;
            in++;
            ilen--;
        }
    }
    return true;
}

bool finalize_areion_512_opp(uint8_t *out, size_t *olen, size_t olimit, uint8_t *tag, areion_512_opp_t *state)
{
    if (olimit < state->partial_len) {
        return false;
    }
    *olen = 0;
    if (state->ad_partial_len > 0) {
        opp_absorb_data(&state->Ma, state->ad_buf, state->ad_partial_len, true);
        state->ad_partial_len = 0;
    }

    if (state->partial_len > 0) {
        if (state->enc) {
            opp_encrypt_data(&state->Me, out, state->buf, state->partial_len, true);
        } else {
            opp_decrypt_data(&state->Me, out, state->buf, state->partial_len, true);
        }
        out += state->partial_len;
        *olen += state->partial_len;
        state->partial_len = 0;
    }

    if (state->enc) {
        opp_finalise(&state->Ma, &state->Me, tag);
    } else {
        unsigned char tag_computed[BYTES(OPP_T)];
        opp_finalise(&state->Ma, &state->Me, tag_computed);
        if (opp_verify_tag(tag_computed, tag) != 0) {
            return false;
        }
    }

    return true;
}
