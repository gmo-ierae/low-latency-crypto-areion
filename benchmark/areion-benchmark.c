/* Copyright (c) 2025 GMO Cybersecurity by Ierae, Inc. All rights reserved. */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "areion.h"
#include "perf.h"

struct perf_fds perf;

static void setup_perf()
{
    if (!open_perf(&perf)) {
        perror("SYS_perf_event_open");
        fprintf(stderr, "check '/proc/sys/kernel/perf_event_paranoid' <= 2\n");
        exit(1);
    }
}

static void stop_perf()
{
    close_perf(&perf);
}

static void report_perf(const char *function, uint64_t n_bytes)
{
    struct perf_count count;
    read_perf(&perf, &count);
    printf("%s: %g, %g\n", function, (double)count.cycles / n_bytes, (double)count.instructions / count.cycles);
}

static void report_perf_len(const char *function, int len, uint64_t n_bytes)
{
    struct perf_count count;
    read_perf(&perf, &count);
    printf("%s(%d): %g, %g\n", function, len, (double)count.cycles / n_bytes, (double)count.instructions / count.cycles);
}

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

        reset_perf(&perf);
        double n_bytes = 0;
        for (int i = 0; i < NUMBER_OF_LOOPS; i++) {
            permute_areion_256u8(out, in);
            n_bytes += sizeof in;
            permute_areion_256u8(in, out);
            n_bytes += sizeof out;
        }
        blackhole(in, sizeof in);
        report_perf("permute_areion_256u8", n_bytes);
    }
    {
        uint8_t in[32];
        uint8_t out[32];
        fill(in, sizeof in);

        reset_perf(&perf);
        double n_bytes = 0;
        for (int i = 0; i < NUMBER_OF_LOOPS; i++) {
            inverse_areion_256u8(out, in);
            n_bytes += sizeof in;
            inverse_areion_256u8(in, out);
            n_bytes += sizeof out;
        }
        blackhole(in, sizeof in);
        report_perf("inverse_areion_256u8", n_bytes);
    }
    {
        uint8_t in[64];
        uint8_t out[64];
        fill(in, sizeof in);

        reset_perf(&perf);
        double n_bytes = 0;
        for (int i = 0; i < NUMBER_OF_LOOPS; i++) {
            permute_areion_512u8(out, in);
            n_bytes += sizeof in;
            permute_areion_512u8(in, out);
            n_bytes += sizeof out;
        }
        blackhole(in, sizeof in);
        report_perf("permute_areion_512u8", n_bytes);
    }
    {
        uint8_t in[64];
        uint8_t out[64];
        fill(in, sizeof in);

        reset_perf(&perf);
        double n_bytes = 0;
        for (int i = 0; i < NUMBER_OF_LOOPS; i++) {
            inverse_areion_512u8(out, in);
            n_bytes += sizeof in;
            inverse_areion_512u8(in, out);
            n_bytes += sizeof out;
        }
        blackhole(in, sizeof in);
        report_perf("inverse_areion_512u8", n_bytes);
    }
}

static void benchmark_hashes()
{
    {
        uint8_t in[32];
        uint8_t out[32];
        fill(in, sizeof in);

        reset_perf(&perf);
        double n_bytes = 0;
        for (int i = 0; i < NUMBER_OF_LOOPS; i++) {
            crypto_hash_areion_256_dm(in, out);
            n_bytes += sizeof in;
            crypto_hash_areion_256_dm(out, in);
            n_bytes += sizeof out;
        }
        blackhole(in, sizeof in);
        report_perf("crypto_hash_areion_256_dm", n_bytes);
    }
    {
        uint8_t in[64];
        uint8_t out[64];
        fill(in, sizeof in);
        fill(out, sizeof out);

        reset_perf(&perf);
        double n_bytes = 0;
        for (int i = 0; i < NUMBER_OF_LOOPS; i++) {
            crypto_hash_areion_512_dm(in, out);
            n_bytes += sizeof in;
            crypto_hash_areion_512_dm(out, in);
            n_bytes += sizeof out;
        }
        blackhole(in, sizeof in);
        report_perf("crypto_hash_areion_512_dm", n_bytes);
    }
    {
        int list[] = {
            16, 32, 48, 64, 80, 96, 112, 128, 256, 512, 1024, 2048, 4096, 0
        };
        for (int k = 0; list[k]; k++) {
            int len = list[k];
            int buffer_len = len < CRYPTO_HASH_AREION_MD_LEN ? CRYPTO_HASH_AREION_MD_LEN : len;
            uint8_t in[buffer_len];
            uint8_t out[buffer_len];
            fill(in, sizeof in);
            fill(out, sizeof out);

            reset_perf(&perf);
            double n_bytes = 0;
            for (int i = 0; i < NUMBER_OF_LOOPS; i++) {
                crypto_hash_areion_md(in, len, out);
                n_bytes += sizeof in;
                crypto_hash_areion_md(out, len, in);
                n_bytes += sizeof out;
            }
            blackhole(in, sizeof in);
            report_perf_len("crypto_hash_areion_md", len, n_bytes);
        }
    }
}

static void benchmark_aead()
{
    {
        for (int len = 32; len < 4096; len *= 2) {
            uint8_t in[len];
            uint8_t out[len];
            uint8_t tag[AREION_256_OPP_TAG_LEN];
            uint8_t h[16];
            uint8_t n[AREION_256_OPP_NONCE_LEN];
            uint8_t k[AREION_256_OPP_KEY_LEN];
            fill(in, sizeof in);
            fill(h, sizeof h);
            fill(n, sizeof n);
            fill(k, sizeof k);

            reset_perf(&perf);
            double n_bytes = 0;
            for (int i = 0; i < NUMBER_OF_LOOPS; i++) {
                encrypt_areion_256_opp(out, tag, h, sizeof h, in, sizeof in, n, k);
                n_bytes += sizeof in;
                encrypt_areion_256_opp(in, tag, h, sizeof h, out, sizeof out, n, k);
                n_bytes += sizeof out;
            }
            blackhole(in, sizeof in);
            report_perf_len("encrypt_areion_256_opp", len, n_bytes);
        }
    }
    {
        for (int len = 32; len < 4096; len *= 2) {
            uint8_t in[len];
            uint8_t out[len];
            uint8_t tag[AREION_512_OPP_TAG_LEN];
            uint8_t h[16];
            uint8_t n[AREION_512_OPP_NONCE_LEN];
            uint8_t k[AREION_512_OPP_KEY_LEN];
            fill(in, sizeof in);
            fill(h, sizeof h);
            fill(n, sizeof n);
            fill(k, sizeof k);

            reset_perf(&perf);
            double n_bytes = 0;
            for (int i = 0; i < NUMBER_OF_LOOPS; i++) {
                encrypt_areion_512_opp(out, tag, h, sizeof h, in, sizeof in, n, k);
                n_bytes += sizeof in;
                encrypt_areion_512_opp(in, tag, h, sizeof h, out, sizeof out, n, k);
                n_bytes += sizeof out;
            }
            blackhole(in, sizeof in);
            report_perf_len("encrypt_areion_512_opp", len, n_bytes);
        }
    }
}

int main(int argc, char **argv)
{
    setup_perf();

    printf("function name: cycles per byte, instructions per cycle\n");
    benchmark_primitives();
    benchmark_hashes();
    benchmark_aead();

    stop_perf();
    return 0;
}
