/* Copyright (c) 2023 GMO Cybersecurity by Ierae, Inc. All rights reserved. */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "areion.h"
#include "cycle.h"

#define NUMBER_OF_LOOPS 12500000

static void fill(uint8_t *dst, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        dst[i] = i;
    }
}

static void benchmark_primitives()
{
    {
        uint8_t in[32];
        uint8_t out[32];
        fill(in, sizeof in);

        ticks t0 = getticks();
        for (int i = 0; i < NUMBER_OF_LOOPS; i++) {
            permute_areion_256u8(out, in);
        }
        ticks t1 = getticks();
        double total_cycle = elapsed(t1, t0);
        total_cycle /= NUMBER_OF_LOOPS;
        total_cycle /= 32;
        printf("permute_areion_256u8: %g\n", total_cycle);
    }
    {
        uint8_t in[32];
        uint8_t out[32];
        fill(in, sizeof in);

        ticks t0 = getticks();
        for (int i = 0; i < NUMBER_OF_LOOPS; i++) {
            inverse_areion_256u8(out, in);
        }
        ticks t1 = getticks();
        double total_cycle = elapsed(t1, t0);
        total_cycle /= NUMBER_OF_LOOPS;
        total_cycle /= 32;
        printf("inverse_areion_256u8: %g\n", total_cycle);
    }
    {
        uint8_t in[64];
        uint8_t out[64];
        fill(in, sizeof in);

        ticks t0 = getticks();
        for (int i = 0; i < NUMBER_OF_LOOPS; i++) {
            permute_areion_512u8(out, in);
        }
        ticks t1 = getticks();
        double total_cycle = elapsed(t1, t0);
        total_cycle /= NUMBER_OF_LOOPS;
        total_cycle /= 32;
        printf("permute_areion_512u8: %g\n", total_cycle);
    }
    {
        uint8_t in[64];
        uint8_t out[64];
        fill(in, sizeof in);

        ticks t0 = getticks();
        for (int i = 0; i < NUMBER_OF_LOOPS; i++) {
            inverse_areion_512u8(out, in);
        }
        ticks t1 = getticks();
        double total_cycle = elapsed(t1, t0);
        total_cycle /= NUMBER_OF_LOOPS;
        total_cycle /= 32;
        printf("inverse_areion_512u8: %g\n", total_cycle);
    }
}

static void benchmark_aead()
{
    {
        for (int len = 32; len < 4096; len *= 2) {
            uint8_t in[len];
            uint8_t out[len];
            uint8_t tag[16];
            uint8_t h[16];
            uint8_t n[16];
            uint8_t k[16];
            fill(in, sizeof in);
            fill(h, sizeof h);
            fill(n, sizeof n);
            fill(k, sizeof k);

            ticks t0 = getticks();
            for (int i = 0; i < NUMBER_OF_LOOPS; i++) {
                encrypt_areion_256_opp(out, tag, h, sizeof h, in, sizeof in, n, k);
            }
            ticks t1 = getticks();
            double total_cycle = elapsed(t1, t0);
            total_cycle /= NUMBER_OF_LOOPS;
            total_cycle /= len;
            printf("encrypt_areion_256_opp,mlen=%d: %g\n", len,total_cycle);
        };
    }
}

int main(int argc, char **argv)
{
    benchmark_primitives();
    benchmark_aead();

    return 0;
}
