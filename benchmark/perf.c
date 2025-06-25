/* Copyright (c) 2025 GMO Cybersecurity by Ierae, Inc. All rights reserved. */

#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "perf.h"

bool open_perf(struct perf_fds *fds)
{
    struct perf_event_attr cycles_attr = {
        .type = PERF_TYPE_HARDWARE,
        .size = sizeof (struct perf_event_attr),
        .config = PERF_COUNT_HW_CPU_CYCLES,
        .exclude_kernel = 1,
        .exclude_hv = 1,
    };
    fds->cycles_fd = syscall(SYS_perf_event_open, &cycles_attr, 0, -1, -1, 0);

    struct perf_event_attr instructions_attr = {
        .type = PERF_TYPE_HARDWARE,
        .size = sizeof (struct perf_event_attr),
        .config = PERF_COUNT_HW_INSTRUCTIONS,
        .exclude_kernel = 1,
        .exclude_hv = 1,
    };
    fds->instructions_fd = syscall(SYS_perf_event_open, &instructions_attr, 0, -1, -1, 0);

    if (fds->cycles_fd < 0 && fds->instructions_fd < 0) {
        return false;
    }
    return true;
}

void close_perf(const struct perf_fds *fds)
{
    close(fds->cycles_fd);
    close(fds->instructions_fd);
}

void reset_perf(const struct perf_fds *fds)
{
    ioctl(fds->cycles_fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fds->instructions_fd, PERF_EVENT_IOC_RESET, 0);
}

bool read_perf(const struct perf_fds *fds, struct perf_count *dst)
{
    int n = read(fds->cycles_fd, &dst->cycles, sizeof (dst->cycles));
    int m = read(fds->instructions_fd, &dst->instructions, sizeof (dst->instructions));
    if (n < 0 || m < 0) {
        return false;
    }
    return true;
}

static volatile uint8_t blackhole_value;

void blackhole(const void *data, size_t len)
{
    const uint8_t *p = data;
    for (size_t i = 0; i < len; i++) {
        blackhole_value ^= p[i];
    }
}
