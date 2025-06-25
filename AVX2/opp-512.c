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
#include "private/areion-private.h"
#include "areion-aesni-parallel.h"

#define PARALLEL_MAX 8

typedef uint64_t opp_word_t;

typedef struct
{
    __m128i s[4];
} opp_state_t;

typedef struct
{
    opp_state_t s[8];
} opp_state8_t;

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
    const __m128i_u *p = (const __m128i_u *)in;
    return (opp_state_t){
        _mm_loadu_si128(&p[0]),
        _mm_loadu_si128(&p[1]),
        _mm_loadu_si128(&p[2]),
        _mm_loadu_si128(&p[3])
    };
}

static inline void store_state(void *out, const opp_state_t *s)
{
    __m128i_u *p = (__m128i_u *)out;
    _mm_storeu_si128(&p[0], s->s[0]);
    _mm_storeu_si128(&p[1], s->s[1]);
    _mm_storeu_si128(&p[2], s->s[2]);
    _mm_storeu_si128(&p[3], s->s[3]);
}

static inline opp_state_t zero_state()
{
    return (opp_state_t){
        _mm_setzero_si128(),
        _mm_setzero_si128(),
        _mm_setzero_si128(),
        _mm_setzero_si128()
    };
}

static inline opp_state_t xor_state(opp_state_t x, opp_state_t y)
{
    opp_state_t s;
    for (int i = 0; i < 4; i++) {
        s.s[i] = x.s[i] ^ y.s[i];
    }
    return s;
}

static inline opp_word_t rotl(opp_word_t x, int c)
{
    return (x << c) | (x >> (BITS(x) - c));
}

static inline void opp_permute(opp_state_t *state)
{
    perm_512_xmm_parallel(state->s, 1);
}

static inline void opp_permute_inverse(opp_state_t *state)
{
    inv_perm_512_xmm_parallel(state->s, 1);
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
    s.s[0] = _mm_set_epi64x(_mm_extract_epi64(x.s[1], 0), _mm_extract_epi64(x.s[0], 1));
    s.s[1] = _mm_set_epi64x(_mm_extract_epi64(x.s[2], 0), _mm_extract_epi64(x.s[1], 1));
    s.s[2] = _mm_set_epi64x(_mm_extract_epi64(x.s[3], 0), _mm_extract_epi64(x.s[2], 1));
    s.s[3] = _mm_set_epi64x(
        rotl(_mm_extract_epi64(x.s[0], 0), 29) ^ (_mm_extract_epi64(x.s[0], 1) << 9),
        _mm_extract_epi64(x.s[3], 1)
    );
    return s;
}

/* alpha(x) = phi(x) */
static inline opp_state_t opp_alpha(opp_state_t x)
{
    return opp_phi(x);
}

typedef struct {
    opp_word_t M[8 + PARALLEL_MAX];
} opp_masks_t;

static inline opp_masks_t opp_alpha_parallel(opp_state_t x, int width)
{
    opp_masks_t m;
    for (int i = 0; i < 4; i++) {
        _mm_storeu_si128((__m128i_u *)&m.M[2 * i], x.s[i]);
    }
    for (int i = 0; i < width; i++) {
        m.M[i + 8] = rotl(m.M[i], 29) ^ (m.M[i + 1] << 9);
    }
    return m;
}

static inline opp_state_t opp_alpha_get(const opp_masks_t *m, int i)
{
    opp_state_t s;
    for (int j = 0; j < 4; j++) {
        s.s[j] = _mm_loadu_si128((const __m128i_u *)&m->M[i + 2 * j]);
    }
    return s;
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

static inline void load_blocks(__m128i *inb, const uint8_t *in, int width)
{
    const __m128i_u *p = (const __m128i_u *)in;
    for (int i = 0; i < 4 * width; i++) {
        inb[i] = _mm_loadu_si128(&p[i]);
    }
}

static inline void store_blocks(uint8_t *out, __m128i *outb, int width)
{
    __m128i_u *p = (__m128i_u *)out;
    for (int i = 0; i < 4 * width; i++) {
        _mm_storeu_si128(&p[i], outb[i]);
    }
}

static inline void accumulate_blocks(opp_state_t *state, const __m128i *p, int width)
{
    for (int i = 0; i < width; i++) {
        for (int j = 0; j < 4; j++) {
            state->s[j] = _mm_xor_si128(state->s[j], p[4 * i + j]);
        }
    }
}

static inline void opp_mem_parallel(__m128i *blocks, opp_state_t *mask, int width, bool inverse)
{
    opp_masks_t masks = opp_alpha_parallel(*mask, width);
    for (int i = 0; i < width; i++) {
        opp_state_t mask = opp_alpha_get(&masks, i);
        for (int j = 0; j < 4; j++) {
            blocks[4 * i + j] = _mm_xor_si128(blocks[4 * i + j], mask.s[j]);
        }
    }
    if (inverse) {
        inv_perm_512_xmm_parallel(blocks, width);
    } else {
        perm_512_xmm_parallel(blocks, width);
    }
    for (int i = 0; i < width; i++) {
        opp_state_t mask = opp_alpha_get(&masks, i);
        for (int j = 0; j < 4; j++) {
            blocks[4 * i + j] = _mm_xor_si128(blocks[4 * i + j], mask.s[j]);
        }
    }
    *mask = opp_alpha_get(&masks, width);
}

static inline void opp_absorb_block(opp_state_t *state, opp_state_t *mask, const uint8_t *in, int width)
{
    __m128i blocks[4 * PARALLEL_MAX];
    load_blocks(blocks, in, width);
    opp_mem_parallel(blocks, mask, width, false);
    accumulate_blocks(state, blocks, width);
}

static inline void opp_absorb_lastblock(opp_state_t *state, opp_state_t *mask, const uint8_t * in, size_t inlen)
{
    *mask = opp_beta(*mask);
    opp_state_t inb = opp_pad(in, inlen);
    opp_state_t outb = opp_mem(inb, *mask);
    *state = xor_state(*state, outb);
}

static inline void opp_encrypt_block(opp_state_t *state, opp_state_t *mask, uint8_t * out, const uint8_t * in, int width)
{
    __m128i blocks[4 * PARALLEL_MAX];
    load_blocks(blocks, in, width);
    accumulate_blocks(state, blocks, width);
    opp_mem_parallel(blocks, mask, width, false);
    store_blocks(out, blocks, width);
}

static inline void opp_encrypt_lastblock(opp_state_t *state, opp_state_t *mask, uint8_t * out, const uint8_t * in, size_t inlen)
{
    *mask = opp_beta(*mask);
    opp_state_t inb = opp_pad(in, inlen);
    opp_state_t block = opp_mem(zero_state(), *mask);
    opp_state_t outb = xor_state(block, inb);
    store_state_trunc(out, inlen, &outb);
    *state = xor_state(*state, inb);
}

static inline void opp_decrypt_block(opp_state_t *state, opp_state_t *mask, uint8_t * out, const uint8_t * in, int width)
{
    __m128i blocks[4 * PARALLEL_MAX];
    load_blocks(blocks, in, width);
    opp_mem_parallel(blocks, mask, width, true);
    accumulate_blocks(state, blocks, width);
    store_blocks(out, blocks, width);
}

static inline void opp_decrypt_lastblock(opp_state_t *state, opp_state_t *mask, uint8_t * out, const uint8_t * in, size_t inlen)
{
    *mask = opp_beta(*mask);
    opp_state_t inb = opp_pad(in, inlen);
    opp_state_t block = opp_mem(zero_state(), *mask);
    opp_state_t outb = xor_state(block, inb);
    store_state_trunc(out, inlen, &outb);
    opp_state_t plainb = opp_pad(out, inlen);
    *state = xor_state(*state, plainb);
}

/* low-level interface functions */
static void opp_absorb_data(opp_state_t *state, opp_state_t *mask, const unsigned char * in, size_t inlen)
{
    while (inlen >= 8 * BYTES(OPP_B))
    {
        opp_absorb_block(state, mask, in, 8);
        inlen -= 8 * BYTES(OPP_B);
        in    += 8 * BYTES(OPP_B);
    }
    while (inlen >= BYTES(OPP_B))
    {
        opp_absorb_block(state, mask, in, 1);
        inlen -= BYTES(OPP_B);
        in    += BYTES(OPP_B);
    }
    if (inlen > 0)
    {
        opp_absorb_lastblock(state, mask, in, inlen);
    }
}

static void opp_encrypt_data(opp_state_t *state, opp_state_t *mask, unsigned char * out, const unsigned char * in, size_t inlen)
{
    while (inlen >= 8 * BYTES(OPP_B))
    {
        opp_encrypt_block(state, mask, out, in, 8);
        inlen -= 8 * BYTES(OPP_B);
        in    += 8 * BYTES(OPP_B);
        out   += 8 * BYTES(OPP_B);
    }
    while (inlen >= BYTES(OPP_B))
    {
        opp_encrypt_block(state, mask, out, in, 1);
        inlen -= BYTES(OPP_B);
        in    += BYTES(OPP_B);
        out   += BYTES(OPP_B);
    }
    if (inlen > 0)
    {
        opp_encrypt_lastblock(state, mask, out, in, inlen);
    }
}

static void opp_decrypt_data(opp_state_t *state, opp_state_t *mask, unsigned char * out, const unsigned char * in, size_t inlen)
{
    while (inlen >= 8 * BYTES(OPP_B))
    {
        opp_decrypt_block(state, mask, out, in, 8);
        inlen -= 8 * BYTES(OPP_B);
        in    += 8 * BYTES(OPP_B);
        out   += 8 * BYTES(OPP_B);
    }
    while (inlen >= BYTES(OPP_B))
    {
        opp_decrypt_block(state, mask, out, in, 1);
        inlen -= BYTES(OPP_B);
        in    += BYTES(OPP_B);
        out   += BYTES(OPP_B);
    }
    if (inlen > 0)
    {
        opp_decrypt_lastblock(state, mask, out, in, inlen);
    }
}

static void opp_finalise(opp_state_t sa, opp_state_t se, opp_state_t mask, unsigned char *tag)
{
    opp_state_t m = opp_beta(opp_beta(mask));
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
    opp_state_t sa = zero_state();
    opp_state_t se = zero_state();
    opp_state_t la = opp_init_mask(key, nonce);
    opp_state_t le = opp_gamma(la);

    /* absorb header */
    opp_absorb_data(&sa, &la, h, hlen);

    /* encrypt message */
    opp_encrypt_data(&se, &le, c, m, mlen);

    /* finalise and extract tag */
    opp_finalise(sa, se, le, tag);
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
    opp_state_t sa = zero_state();
    opp_state_t se = zero_state();
    opp_state_t la = opp_init_mask(key, nonce);
    opp_state_t le = opp_gamma(la);

    /* absorb header */
    opp_absorb_data(&sa, &la, h, hlen);

    /* decrypt message */
    opp_decrypt_data(&se, &le, m, c, clen);

    /* finalise and extract tag */
    unsigned char cipher_tag[BYTES(OPP_T)];
    opp_finalise(sa, se, le, cipher_tag);

    /* verify tag */
    int result = opp_verify_tag(tag, cipher_tag);

    return result;
}

struct areion_512_opp_t
{
    opp_state_t Sa;
    opp_state_t Se;
    opp_state_t La;
    opp_state_t Le;
    uint8_t ad_buf[64];
    uint8_t buf[64];
    int ad_partial_len;
    int partial_len;
    bool enc;
};

areion_512_opp_t *alloc_areion_512_opp()
{
    return malloc(sizeof (areion_512_opp_t));
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
    state->Sa = zero_state();
    state->Se = zero_state();
    state->La = opp_init_mask(k, n);
    state->Le = opp_gamma(state->La);
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
                opp_absorb_block(&state->Sa, &state->La, state->ad_buf, 1);
                state->ad_partial_len = 0;
            }
        }
        while (ilen >= BYTES(OPP_B)) {
            opp_absorb_block(&state->Sa, &state->La, in, 1);
            in += BYTES(OPP_B);
            ilen -= BYTES(OPP_B);
        }
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
                    opp_encrypt_block(&state->Se, &state->Le, out, state->buf, 1);
                } else {
                    opp_decrypt_block(&state->Se, &state->Le, out, state->buf, 1);
                }
                state->partial_len = 0;
                out += BYTES(OPP_B);
                *olen += BYTES(OPP_B);
            }
        }
        while (ilen >= BYTES(OPP_B)) {
            if (state->enc) {
                opp_encrypt_block(&state->Se, &state->Le, out, in, 1);
            } else {
                opp_decrypt_block(&state->Se, &state->Le, out, in, 1);
            }
            in += BYTES(OPP_B);
            ilen -= BYTES(OPP_B);
            out += BYTES(OPP_B);
            *olen += BYTES(OPP_B);
        }
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
        opp_absorb_lastblock(&state->Sa, &state->La, state->ad_buf, state->ad_partial_len);
        state->ad_partial_len = 0;
    }

    if (state->partial_len > 0) {
        if (state->enc) {
            opp_encrypt_lastblock(&state->Se, &state->Le, out, state->buf, state->partial_len);
        } else {
            opp_decrypt_lastblock(&state->Se, &state->Le, out, state->buf, state->partial_len);
        }
        out += state->partial_len;
        *olen += state->partial_len;
        state->partial_len = 0;
    }

    if (state->enc) {
        opp_finalise(state->Sa, state->Se, state->Le, tag);
    } else {
        unsigned char tag_computed[BYTES(OPP_T)];
        opp_finalise(state->Sa, state->Se, state->Le, tag_computed);
        if (opp_verify_tag(tag_computed, tag) != 0) {
            return false;
        }
    }

    return true;
}
