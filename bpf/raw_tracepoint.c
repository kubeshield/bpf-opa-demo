// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 Facebook */
#include <uapi/linux/bpf.h>
#include <asm/unistd.h>
#include <linux/ptrace.h>
#include "bpf_helpers.h"

struct data_t {
    char filename[64];
};

struct bpf_map_def SEC("maps/my_map") my_map = {
        .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
        .key_size = sizeof(int),
        .value_size = sizeof(u32),
        .max_entries = 4,
};

SEC("raw_tracepoint/sys_enter")
int trace_execve(struct bpf_raw_tracepoint_args *ctx)
{
    // sys_enter takes two arguments
    // struct pt_regs *regs, long id
    long syscall_id;
    syscall_id = ctx->args[1];

    if (syscall_id != __NR_execve) {
        return 0;
    }

    struct pt_regs *regs;
    regs = (struct pt_regs *)ctx->args[0];

    struct data_t data;

    const char *filename;
    bpf_probe_read(&filename, sizeof(filename), &regs->di);
    bpf_probe_read_str(data.filename, sizeof(data.filename), filename);

    bpf_perf_event_output(ctx, &my_map, 0, &data, sizeof(data));

    return 0;
}

char _license[] SEC("license") = "GPL";
