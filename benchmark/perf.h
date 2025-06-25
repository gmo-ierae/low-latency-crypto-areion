/* Copyright (c) 2025 GMO Cybersecurity by Ierae, Inc. All rights reserved. */

#pragma once
#include <inttypes.h>
#include <stdbool.h>

struct perf_fds
{
    int cycles_fd;
    int instructions_fd;
};

struct perf_count
{
    uint64_t cycles;
    uint64_t instructions;
};

bool open_perf(struct perf_fds *fds);
void close_perf(const struct perf_fds *fds);
void reset_perf(const struct perf_fds *fds);
bool read_perf(const struct perf_fds *fds, struct perf_count *dst);

void blackhole(const void *data, size_t len);
