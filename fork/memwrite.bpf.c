/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* MemGuard memory-store write capture probe (fork of AgentSight).
 * Detects writes to LLM agent long-term memory stores and captures the
 * payload for user-space poison analysis.
 *
 * Design notes:
 *  - kprobe vfs_write: kernel-level, gets struct file* directly so the
 *    filename can be read in-kernel without fd->path tracking.
 *  - Filename prefix filter: only memory-store files are captured, keeping
 *    userspace traffic near zero on busy hosts.
 *  - Head+tail dual-window capture: sqlite cells grow from the end of the
 *    page, so poison text almost always lands in the page tail. Capturing
 *    only the head window would miss most real poison writes.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "memwrite.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* Memory-store filename prefixes, set via rodata (e.g. "ehragent_memory").
 * Up to MAX_WATCH_PREFIXES, comma-separated on the loader CLI. */
const volatile char watch_prefix[MAX_WATCH_PREFIXES][WATCH_PREFIX_LEN] = {};
const volatile __u32 watch_prefix_count = 0;

static __always_inline bool match_prefix(const char *s)
{
    /* clang unrolls this tiny loop; no libc dep in BPF.
     * Outer loop unrolls to MAX_WATCH_PREFIXES static iterations (each
     * checking `p >= count` first), keeping the verifier happy. */
#pragma unroll
    for (int p = 0; p < MAX_WATCH_PREFIXES; p++) {
        if (p >= watch_prefix_count)
            break;
        bool matched = true;
#pragma unroll
        for (int i = 0; i < WATCH_PREFIX_LEN; i++) {
            char c = s[i];
            char pfx = watch_prefix[p][i];
            if (pfx == '\0')
                break;              /* prefix fully matched */
            if (c == '\0' || c != pfx) {
                matched = false;    /* mismatch or name shorter than prefix */
                break;
            }
        }
        if (matched)
            return true;
    }
    return false;
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(memwrite_vfs_write, struct file *file,
               const void *buf, size_t count, loff_t *pos)
{
    struct memwrite_event *e;
    struct dentry *dentry;
    const unsigned char *name;
    const unsigned char *parent_name;
    char fname[FILENAME_LEN];
    size_t head_len, tail_len;
    loff_t off;

    if (!file || !buf || count == 0)
        return 0;

    /* Only capture memory-store files (prefix match on basename). */
    dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry)
        return 0;
    name = BPF_CORE_READ(dentry, d_name.name);
    if (!name)
        return 0;
    /* Read the name into a stack buffer: nested pointers from BPF_CORE_READ
     * are opaque to the verifier (cannot be dereferenced), but helpers can
     * copy from them. Stack buffers are always valid for direct access. */
    if (bpf_probe_read_kernel_str(fname, sizeof(fname), name) < 0)
        return 0;
    if (!match_prefix(fname))
        return 0;

    /* Reserve the fixed-size event from the ring buffer. */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = (u32)bpf_get_current_pid_tgid();
    e->timestamp_ns = bpf_ktime_get_ns();
    e->count = count;
    off = 0;
    if (pos)
        bpf_probe_read_kernel(&off, sizeof(off), pos);
    e->offset = off < 0 ? 0 : (u64)off;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* basename + parent basename (parents like /root, /tmp are often useful). */
    __builtin_memcpy(e->filename, fname, sizeof(fname));
    parent_name = BPF_CORE_READ(dentry, d_parent, d_name.name);
    if (parent_name)
        bpf_probe_read_kernel_str(e->parent, sizeof(e->parent), parent_name);
    else
        e->parent[0] = '\0';

    /* Head window: first PAYLOAD_HALF bytes of the write. */
    head_len = count < PAYLOAD_HALF ? count : PAYLOAD_HALF;
    /* Mask to (2^n - 1): bounds head_len to [0,255] so the verifier can
     * prove non-negativity before passing it to bpf_probe_read_user.
     * Values are <= 128 here, so the mask never changes the result. */
    head_len &= 0xff;
    if (head_len > 0 &&
        bpf_probe_read_user(e->head, head_len, buf) != 0)
        head_len = 0;
    e->head_len = head_len;

    /* Tail window: last PAYLOAD_HALF bytes of the write.
     * Verifier-safe form: use a CONSTANT size for the tail read. The tail
     * window only needs the final stretch of the write; reading exactly
     * PAYLOAD_HALF bytes from (buf + count - PAYLOAD_HALF) is fine and never
     * requires the verifier to prove a variable is non-negative. */
    tail_len = 0;
    {
        u32 tc = (u32)count;
        if (tc > PAYLOAD_HALF) {
            u32 off = tc - PAYLOAD_HALF;
            /* clamp offset to [0, tc - PAYLOAD_HALF) even if tc wraps:
             * off < tc always holds because tc > PAYLOAD_HALF. Offsets into
             * the user buffer stay inside the write region. */
            if (bpf_probe_read_user(e->tail, PAYLOAD_HALF,
                                    (const char *)buf + off) == 0)
                tail_len = PAYLOAD_HALF;
        }
    }
    e->tail_len = tail_len;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/vfs_writev")
int BPF_KPROBE(memwrite_vfs_writev, struct file *file,
               const struct iovec *vec, unsigned long vlen,
               loff_t *pos)
{
    /* writev: capture the first iovec segment only (cheap partial window).
     * Full iovec walk is deferred to userspace if deeper coverage is needed. */
    struct memwrite_event *e;
    struct iovec iov = {};
    const void *buf;
    struct dentry *dentry;
    const unsigned char *name;
    char fname[FILENAME_LEN];

    if (!file || !vec || vlen == 0)
        return 0;

    dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry)
        return 0;
    name = BPF_CORE_READ(dentry, d_name.name);
    if (!name)
        return 0;
    if (bpf_probe_read_kernel_str(fname, sizeof(fname), name) < 0)
        return 0;
    if (!match_prefix(fname))
        return 0;

    if (bpf_probe_read_user(&iov, sizeof(iov), vec) != 0 || iov.iov_len == 0)
        return 0;
    buf = iov.iov_base;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = (u32)bpf_get_current_pid_tgid();
    e->timestamp_ns = bpf_ktime_get_ns();
    e->count = iov.iov_len;
    if (pos)
        bpf_probe_read_kernel(&e->offset, sizeof(e->offset), pos);
    else
        e->offset = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->filename, fname, sizeof(fname));
    e->parent[0] = '\0';

    /* Head window: capture the first PAYLOAD_HALF bytes when the segment
     * is large enough. A CONSTANT-size read keeps the verifier happy:
     * iov_len comes from user memory, so variable-length reads need a
     * non-negativity proof the verifier refuses to infer (clang reloads
     * iov_len from stack and drops the branch range). Small writes
     * (< PAYLOAD_HALF) yield no head window (head_len=0), acceptable
     * for poison scanning (payloads are long texts). */
    e->head_len = 0;
    if (iov.iov_len >= PAYLOAD_HALF) {
        if (bpf_probe_read_user(e->head, PAYLOAD_HALF, buf) == 0)
            e->head_len = PAYLOAD_HALF;
    }
    e->tail_len = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}