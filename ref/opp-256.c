/*
    OPP - MEM AEAD source code package

    :copyright: (c) 2015 by Philipp Jovanovic and Samuel Neves
    :copyright: (c) 2023 by GMO Cybersecurity by Ierae, Inc. 

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

typedef opp_word_t opp_state_t[4];

#if defined(OPP_DEBUG)
#include <stdio.h>
void print_state(uint64_t S[16]);
void print_bytes(const uint8_t * in, size_t inlen);
#endif

#define OPP_W 64           /* word size */
#define OPP_T (OPP_W *  2) /* tag size */
#define OPP_N (OPP_W *  2) /* nonce size */
#define OPP_K (OPP_W *  2) /* key size */
#define OPP_B (OPP_W *  4) /* permutation width */

#if AREION_256_OPP_TAG_LEN * 8 != OPP_T
#error "AREION_256_OPP_TAG_LEN * 8 != OPP_T"
#endif
#if AREION_256_OPP_NONCE_LEN * 8 != OPP_K
#error "AREION_256_OPP_NONCE_LEN * 8 != OPP_N"
#endif
#if AREION_256_OPP_KEY_LEN * 8 != OPP_K
#error "AREION_256_OPP_KEY_LEN * 8 != OPP_K"
#endif

/* Workaround for C89 compilers */
#if !defined(__cplusplus) && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L)
  #if   defined(_MSC_VER)
    #define OPP_INLINE __inline
  #elif defined(__GNUC__)
    #define OPP_INLINE __inline__
  #else
    #define OPP_INLINE
  #endif
#else
  #define OPP_INLINE inline
#endif

#define BITS(x) (sizeof(x) * CHAR_BIT)
#define BYTES(x) (((x) + 7) / 8)
#define WORDS(x) (((x) + (OPP_W-1)) / OPP_W)

static OPP_INLINE uint64_t load64(const void * in)
{
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    uint64_t v;
    memcpy(&v, in, sizeof v);
    return v;
#else
    const uint8_t * p = (const uint8_t *)in;
    return ((uint64_t)p[0] <<  0) |
           ((uint64_t)p[1] <<  8) |
           ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
#endif
}

static OPP_INLINE void store64(void * out, const uint64_t v)
{
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    memcpy(out, &v, sizeof v);
#else
    uint8_t * p = (uint8_t *)out;
    p[0] = (uint8_t)(v >>  0);
    p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
#endif
}

#define LOAD load64
#define STORE store64
#define ROTL(x, c) ( ((x) << (c)) | ((x) >> (BITS(x) - (c))) )

static void* (* const volatile burn)(void*, int, size_t) = memset;

static OPP_INLINE void opp_permute(opp_state_t state)
{
    permute_areion_256u8((uint8_t *)state, (uint8_t *)state);
}

static OPP_INLINE void opp_permute_inverse(opp_state_t state)
{
    inverse_areion_256u8((uint8_t *)state, (uint8_t *)state);
}

static OPP_INLINE void opp_pad(uint8_t * out, const uint8_t * in, const size_t inlen)
{
    memset(out, 0, BYTES(OPP_B));
    memcpy(out, in, inlen);
    out[inlen] = 0x01;
}

static OPP_INLINE void opp_init_mask(opp_state_t mask, const unsigned char * k, const unsigned char * n)
{
    memcpy(&mask[0], n, 16);
    memcpy(&mask[2], k, 16);

    /* apply permutation */
    opp_permute(mask);

#if defined(OPP_DEBUG)
    printf("SETUP MASK:\n");
    print_state(mask);
#endif

}

/* alpha(x) = phi(x) */
static OPP_INLINE void opp_alpha(opp_state_t mask)
{
    size_t i;
    opp_word_t * L = mask;
    opp_word_t t = ROTL(L[0], 3) ^ (L[3] >> 5);
    for (i = 0; i < WORDS(OPP_B) - 1; ++i)
    {
        L[i] = L[i+1];
    }
    L[i] = t;
}

/* beta(x) = phi(x) ^ x */
static OPP_INLINE void opp_beta(opp_state_t mask)
{
    size_t i;
    opp_word_t * L = mask;
    opp_word_t t = ROTL(L[0], 3) ^ (L[3] >> 5);
    for (i = 0; i < WORDS(OPP_B) - 1; ++i)
    {
        L[i] ^= L[i+1];
    }
    L[i] ^= t;
}

/* gamma(x) = phi^2(x) ^ phi(x) ^ x */
static OPP_INLINE void opp_gamma(opp_state_t mask)
{
    size_t i;
    opp_word_t * L = mask;
    opp_word_t t0 = ROTL(L[0], 3) ^ (L[3] >> 5);
    opp_word_t t1 = ROTL(L[1], 3) ^ (t0 >> 5);
    for (i = 0; i < WORDS(OPP_B) - 2; ++i)
    {
        L[i] ^= L[i+1] ^ L[i+2];
    }
    L[i] ^= (L[i + 1] ^ t0);
    L[i + 1] ^= (t0 ^ t1);
}

static OPP_INLINE void opp_absorb_block(opp_state_t state, opp_state_t mask, const uint8_t * in)
{
    size_t i;
    const size_t n = WORDS(OPP_B);
    opp_state_t block;
    opp_word_t * B = block;
    opp_word_t * S = state;
    opp_word_t * L = mask;

    /* load data and XOR mask */
    for (i = 0; i < n; ++i)
    {
        B[i] = LOAD(in + i * BYTES(OPP_W)) ^ L[i];
    }

    /* apply permutation */
    opp_permute(block);

    /* XOR mask and absorb into state */
    for (i = 0; i < n; ++i)
    {
        S[i] ^= B[i] ^ L[i];
    }

#if defined(OPP_DEBUG)
    printf("ABSORBING BLOCK\n");
    printf("IN:\n");
    print_bytes(in, BYTES(OPP_B));
    printf("\nSTATE:\n");
    print_state(state);
    printf("MASK:\n");
    print_state(mask);
#endif
}

static OPP_INLINE void opp_absorb_lastblock(opp_state_t state, opp_state_t mask, const uint8_t * in, size_t inlen)
{
    size_t i;
    const size_t n = WORDS(OPP_B);
    opp_state_t block;
    opp_word_t * B = block;
    opp_word_t * S = state;
    opp_word_t * L = mask;
    uint8_t lastblock[BYTES(OPP_B)];

    opp_pad(lastblock, in, inlen);

    /* load data and XOR mask */
    for (i = 0; i < n; ++i)
    {
        B[i] = LOAD(lastblock + i * BYTES(OPP_W)) ^ L[i];
    }

    /* apply permutation */
    opp_permute(block);

    /* XOR mask and absorb into state */
    for (i = 0; i < n; ++i)
    {
        S[i] ^= B[i] ^ L[i];
    }

#if defined(OPP_DEBUG)
    printf("ABSORBING LASTBLOCK\n");
    printf("IN:\n");
    print_bytes(in, inlen);
    printf("\nSTATE:\n");
    print_state(state);
    printf("MASK:\n");
    print_state(mask);
#endif
    burn(lastblock, 0, BYTES(OPP_B));
}

static OPP_INLINE void opp_encrypt_block(opp_state_t state, opp_state_t mask, uint8_t * out, const uint8_t * in)
{
    size_t i;
    const size_t n = WORDS(OPP_B);
    opp_state_t block;
    opp_word_t * B = block;
    opp_word_t * S = state;
    opp_word_t * L = mask;

    /* load message and XOR mask */
    for (i = 0; i < n; ++i)
    {
        B[i] = LOAD(in + i * BYTES(OPP_W)) ^ L[i];
    }

    /* apply permutation */
    opp_permute(block);

    /* XOR mask to block and store as ciphertext, XOR message to state */
    for (i = 0; i < n; ++i)
    {
        S[i] ^= LOAD(in + i * BYTES(OPP_W));
        STORE(out + i * BYTES(OPP_W), B[i] ^ L[i]);
    }

#if defined(OPP_DEBUG)
    printf("ENCRYPTING BLOCK\n");
    printf("IN:\n");
    print_bytes(in, BYTES(OPP_B));
    printf("OUT:\n");
    print_bytes(out, BYTES(OPP_B));
    printf("STATE:\n");
    print_state(state);
    printf("MASK:\n");
    print_state(mask);
#endif
}

static OPP_INLINE void opp_encrypt_lastblock(opp_state_t state, opp_state_t mask, uint8_t * out, const uint8_t * in, size_t inlen)
{
    size_t i;
    const size_t n = WORDS(OPP_B);
    opp_state_t block;
    opp_word_t * B = block;
    opp_word_t * S = state;
    opp_word_t * L = mask;
    uint8_t lastblock[BYTES(OPP_B)];

    /* load block with mask */
    for (i = 0; i < n; ++i)
    {
        B[i] = L[i];
    }

    /* apply permutation */
    opp_permute(block);

    /* XOR padded message to state, XOR padded message and mask to block, and extract ciphertext */
    opp_pad(lastblock, in, inlen);
    for (i = 0; i < WORDS(OPP_B); ++i)
    {
        S[i] ^= LOAD(lastblock + i * BYTES(OPP_W));
        STORE(lastblock + i * BYTES(OPP_W), B[i] ^ L[i] ^ LOAD(lastblock + i * BYTES(OPP_W)));
    }
    memcpy(out, lastblock, inlen);

#if defined(OPP_DEBUG)
    printf("ENCRYPTING LASTBLOCK\n");
    printf("IN:\n");
    print_bytes(in, inlen);
    printf("OUT:\n");
    print_bytes(out, inlen);
    printf("STATE:\n");
    print_state(state);
    printf("MASK:\n");
    print_state(mask);
#endif
    burn(lastblock, 0, BYTES(OPP_B));
}

static OPP_INLINE void opp_decrypt_block(opp_state_t state, opp_state_t mask, uint8_t * out, const uint8_t * in)
{
    size_t i;
    const size_t n = WORDS(OPP_B);
    opp_state_t block;
    opp_word_t * B = block;
    opp_word_t * S = state;
    opp_word_t * L = mask;

    /* load ciphertext and XOR mask */
    for (i = 0; i < n; ++i)
    {
        B[i] = LOAD(in + i * BYTES(OPP_W)) ^ L[i];
    }

    /* apply inverse permutation */
    opp_permute_inverse(block);

    /* XOR ciphertext to state, XOR mask to block, and extract message */
    for (i = 0; i < n; ++i)
    {
        STORE(out + i * BYTES(OPP_W), B[i] ^ L[i]);
        S[i] ^= LOAD(out + i * BYTES(OPP_W));
    }

#if defined(OPP_DEBUG)
    printf("DECRYPTING BLOCK\n");
    printf("IN:\n");
    print_bytes(in, BYTES(OPP_B));
    printf("OUT:\n");
    print_bytes(out, BYTES(OPP_B));
    printf("STATE:\n");
    print_state(state);
    printf("MASK:\n");
    print_state(mask);
#endif
}

static OPP_INLINE void opp_decrypt_lastblock(opp_state_t state, opp_state_t mask, uint8_t * out, const uint8_t * in, size_t inlen)
{
    size_t i;
    const size_t n = WORDS(OPP_B);
    opp_state_t block;
    opp_word_t * B = block;
    opp_word_t * S = state;
    opp_word_t * L = mask;
    uint8_t lastblock[BYTES(OPP_B)];

    /* load block with key */
    for (i = 0; i < n; ++i)
    {
        B[i] = L[i];
    }

    /* apply permutation */
    opp_permute(block);

    /* XOR padded ciphertext and key to block, store message */
    opp_pad(lastblock, in, inlen);
    for (i = 0; i < n; ++i)
    {
        STORE(lastblock + i * BYTES(OPP_W), B[i] ^ L[i] ^ LOAD(lastblock + i * BYTES(OPP_W)));
    }
    memcpy(out, lastblock, inlen);

    /* XOR message to state */
    opp_pad(lastblock, out, inlen);
    for (i = 0; i < n; ++i)
    {
        S[i] ^= LOAD(lastblock + i * BYTES(OPP_W));
    }

#if defined(OPP_DEBUG)
    printf("DECRYPTING LASTBLOCK\n");
    printf("IN:\n");
    print_bytes(in, inlen);
    printf("OUT:\n");
    print_bytes(out, inlen);
    printf("STATE:\n");
    print_state(state);
    printf("MASK:\n");
    print_state(mask);
#endif
    burn(lastblock, 0, BYTES(OPP_B));
}

/* low-level interface functions */
static void opp_absorb_data(opp_state_t state, opp_state_t mask, const unsigned char * in, size_t inlen)
{
    while (inlen >= BYTES(OPP_B))
    {
        opp_absorb_block(state, mask, in);
        inlen -= BYTES(OPP_B);
        in    += BYTES(OPP_B);
        opp_alpha(mask);
    }
    if (inlen > 0)
    {
        opp_beta(mask);
        opp_absorb_lastblock(state, mask, in, inlen);
    }
}

static void opp_encrypt_data(opp_state_t state, opp_state_t mask, unsigned char * out, const unsigned char * in, size_t inlen)
{
    opp_gamma(mask);
    while (inlen >= BYTES(OPP_B))
    {
        opp_encrypt_block(state, mask, out, in);
        inlen -= BYTES(OPP_B);
        in    += BYTES(OPP_B);
        out   += BYTES(OPP_B);
        opp_alpha(mask);
    }
    if (inlen > 0)
    {
        opp_beta(mask);
        opp_encrypt_lastblock(state, mask, out, in, inlen);
    }
}

static void opp_decrypt_data(opp_state_t state, opp_state_t mask, unsigned char * out, const unsigned char * in, size_t inlen)
{
    opp_gamma(mask);
    while (inlen >= BYTES(OPP_B))
    {
        opp_decrypt_block(state, mask, out, in);
        inlen -= BYTES(OPP_B);
        in    += BYTES(OPP_B);
        out   += BYTES(OPP_B);
        opp_alpha(mask);
    }
    if (inlen > 0)
    {
        opp_beta(mask);
        opp_decrypt_lastblock(state, mask, out, in, inlen);
    }
}

static void opp_finalise(opp_state_t sa, opp_state_t se, opp_state_t mask, unsigned char *tag)
{
    size_t i;
    const size_t n = WORDS(OPP_B);
    opp_word_t * SA = sa;
    opp_word_t * SE = se;
    opp_word_t * L = mask;
    uint8_t block[BYTES(OPP_B)];

    for (i = 0; i < 2; ++i)
    {
        opp_beta(mask);
    }

    for (i = 0; i < n; ++i)
    {
        SE[i] ^= L[i];
    }

    opp_permute(se);

    for (i = 0; i < n; ++i)
    {
        SA[i] ^= SE[i] ^ L[i];
        STORE(block + i * BYTES(OPP_W), SA[i]);
    }
    memcpy(tag, block, BYTES(OPP_T));

#if defined(OPP_DEBUG)
    printf("EXTRACTING TAG:\n");
    print_bytes(tag, BYTES(OPP_T));
    printf("STATE:\n");
    print_state(sa);
    printf("MASK:\n");
    print_state(mask);
#endif
    burn(block, 0, BYTES(OPP_B));
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
void encrypt_areion_256_opp(
    uint8_t *c,
    uint8_t tag[AREION_256_OPP_TAG_LEN],
    const uint8_t *h, size_t hlen,
    const uint8_t *m, size_t mlen,
    const uint8_t nonce[AREION_256_OPP_NONCE_LEN],
    const uint8_t key[AREION_256_OPP_KEY_LEN])
{
    opp_state_t sa, se, la, le;

    /* init checksums and masks */
    memset(sa, 0, sizeof(opp_state_t));
    memset(se, 0, sizeof(opp_state_t));
    opp_init_mask(la, key, nonce);
    memcpy(le, la, sizeof(opp_state_t));

    /* absorb header */
    opp_absorb_data(sa, la, h, hlen);

    /* encrypt message */
    opp_encrypt_data(se, le, c, m, mlen);

    /* finalise and extract tag */
    opp_finalise(sa, se, le, tag);

    /* empty buffers */
    burn(sa, 0, sizeof(opp_state_t));
    burn(se, 0, sizeof(opp_state_t));
    burn(la, 0, sizeof(opp_state_t));
    burn(le, 0, sizeof(opp_state_t));
}

int decrypt_areion_256_opp(
    uint8_t *m,
    const uint8_t tag[AREION_256_OPP_TAG_LEN],
    const uint8_t *h, size_t hlen,
    const uint8_t *c, size_t clen,
    const uint8_t nonce[AREION_256_OPP_NONCE_LEN],
    const uint8_t key[AREION_256_OPP_KEY_LEN])
{
    int result = -1;
    unsigned char cipher_tag[BYTES(OPP_T)];
    opp_state_t sa, se, la, le;

    /* init checksums and masks */
    memset(sa, 0, sizeof(opp_state_t));
    memset(se, 0, sizeof(opp_state_t));
    opp_init_mask(la, key, nonce);
    memcpy(le, la, sizeof(opp_state_t));

    /* absorb header */
    opp_absorb_data(sa, la, h, hlen);

    /* decrypt message */
    opp_decrypt_data(se, le, m, c, clen);

    /* finalise and extract tag */
    opp_finalise(sa, se, le, cipher_tag);

    /* verify tag */
    result = opp_verify_tag(tag, cipher_tag);

    /* burn decrypted plaintext on authentication failure */
    if(result != 0) { burn(m, 0, clen); }

    /* empty buffers */
    burn(sa, 0, sizeof(opp_state_t));
    burn(se, 0, sizeof(opp_state_t));
    burn(la, 0, sizeof(opp_state_t));
    burn(le, 0, sizeof(opp_state_t));

    return result;
}

struct areion_256_opp_t
{
    opp_state_t Sa;
    opp_state_t Se;
    opp_state_t La;
    opp_state_t Le;
    uint8_t ad_buf[32];
    uint8_t buf[32];
    int ad_partial_len;
    int partial_len;
    bool enc;
};

areion_256_opp_t *alloc_areion_256_opp()
{
    return malloc(sizeof (areion_256_opp_t));
}

void free_areion_256_opp(areion_256_opp_t *state)
{
    free(state);
}

bool initialize_areion_256_opp(bool enc, const uint8_t *n, const uint8_t *k, areion_256_opp_t *state)
{
    state->enc = enc;
    state->ad_partial_len = 0;
    state->partial_len = 0;
    memset(state->Sa, 0, sizeof (opp_state_t));
    memset(state->Se, 0, sizeof (opp_state_t));
    opp_init_mask(state->La, k, n);
    memcpy(state->Le, state->La, sizeof (opp_state_t));
    opp_gamma(state->Le);
    return true;
}

bool update_areion_256_opp(uint8_t *out, size_t *olen, size_t olimit, const uint8_t *in, size_t ilen, areion_256_opp_t *state)
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
                opp_absorb_block(state->Sa, state->La, state->ad_buf);
                state->ad_partial_len = 0;
                opp_alpha(state->La);
            }
        }
        while (ilen >= BYTES(OPP_B)) {
            opp_absorb_block(state->Sa, state->La, in);
            in += BYTES(OPP_B);
            ilen -= BYTES(OPP_B);
            opp_alpha(state->La);
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
                    opp_encrypt_block(state->Se, state->Le, out, state->buf);
                } else {
                    opp_decrypt_block(state->Se, state->Le, out, state->buf);
                }
                state->partial_len = 0;
                out += BYTES(OPP_B);
                *olen += BYTES(OPP_B);
                opp_alpha(state->Le);
            }
        }
        while (ilen >= BYTES(OPP_B)) {
            if (state->enc) {
                opp_encrypt_block(state->Se, state->Le, out, in);
            } else {
                opp_decrypt_block(state->Se, state->Le, out, in);
            }
            in += BYTES(OPP_B);
            ilen -= BYTES(OPP_B);
            out += BYTES(OPP_B);
            *olen += BYTES(OPP_B);
            opp_alpha(state->Le);
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

bool finalize_areion_256_opp(uint8_t *out, size_t *olen, size_t olimit, uint8_t *tag, areion_256_opp_t *state)
{
    if (olimit < state->partial_len) {
        return false;
    }
    *olen = 0;
    if (state->ad_partial_len > 0) {
        opp_beta(state->La);
        opp_absorb_lastblock(state->Sa, state->La, state->ad_buf, state->ad_partial_len);
        state->ad_partial_len = 0;
    }

    if (state->partial_len > 0) {
        opp_beta(state->Le);
        if (state->enc) {
            opp_encrypt_lastblock(state->Se, state->Le, out, state->buf, state->partial_len);
        } else {
            opp_decrypt_lastblock(state->Se, state->Le, out, state->buf, state->partial_len);
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
