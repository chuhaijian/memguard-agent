/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* MemGuard memory-store write capture probe — shared header. */
#ifndef __MEMWRITE_H
#define __MEMWRITE_H

#define TASK_COMM_LEN 16
#define WATCH_PREFIX_LEN 64
#define MAX_WATCH_PREFIXES 8
#define FILENAME_LEN 127
#define PARENT_LEN 64
#define PAYLOAD_HALF 128
#define PAYLOAD_LEN (PAYLOAD_HALF * 2)

struct memwrite_event {
    struct {
        __u64 timestamp_ns;
        __u32 pid;
        __u32 tid;
        __u64 count;
        __u64 offset;
        char comm[TASK_COMM_LEN];
        char filename[FILENAME_LEN];
        char parent[PARENT_LEN];
        __u32 head_len;
        __u32 tail_len;
        char head[PAYLOAD_HALF];
        char tail[PAYLOAD_HALF];
    } __attribute__((packed));
};

#endif /* __MEMWRITE_H */