/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* MemGuard memory-store write capture probe — userspace loader.
 * Streams MEM_WRITE events as JSONL on stdout for the AgentSight collector.
 */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include "memwrite.skel.h"
#include "memwrite.h"
#include "jsonl.h"

static volatile sig_atomic_t stop = 0;
static struct memwrite_bpf *skel = NULL;

static void sig_handler(int sig)
{
    stop = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static const struct argp_option opts[] = {
    { "prefix", 'p', "NAME", 0, "memory-store filename prefix to watch (default ehragent_memory)" },
    { "verbose", 'v', NULL, 0, "verbose libbpf output" },
    {},
};

static char prefix[64] = "ehragent_memory";

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'p':
        snprintf(prefix, sizeof(prefix), "%s", arg);
        break;
    case 'v':
        libbpf_set_print(libbpf_print_fn);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = { opts, parse_arg, NULL, NULL };

/* Resolve an absolute path for the written file so userspace analyzers can
 * re-read the affected byte range (SQLite cell content often sits outside
 * the kernel's head/tail capture windows). Falls back to basename when the
 * writing process already exited (/proc/<pid> is gone). */
static void resolve_path(char *out, size_t outsz, const struct memwrite_event *e)
{
    char link[64];
    char cwd[512];
    ssize_t n;

    snprintf(link, sizeof(link), "/proc/%u/cwd", e->pid);
    n = readlink(link, cwd, sizeof(cwd) - 1);
    if (n > 0) {
        cwd[n] = '\0';
        snprintf(out, outsz, "%s/%s", cwd, e->filename);
    } else {
        snprintf(out, outsz, "%s", e->filename);
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct memwrite_event *e = data;
    char path[FILENAME_LEN + 512];

    if (data_sz < sizeof(struct memwrite_event))
        return 0;

    resolve_path(path, sizeof(path), e);

    printf("{");
    printf("\"timestamp\":%llu,", (unsigned long long)e->timestamp_ns);
    printf("\"event\":\"MEM_WRITE\",");
    printf("\"comm\":\"");
    json_print_escaped(e->comm, strlen(e->comm));
    printf("\",");
    printf("\"pid\":%u,", e->pid);
    printf("\"tid\":%u,", e->tid);
    printf("\"count\":%llu,", (unsigned long long)e->count);
    printf("\"offset\":%llu,", (unsigned long long)e->offset);
    printf("\"path\":\"");
    json_print_escaped(path, strlen(path));
    printf("\",");
    printf("\"filename\":\"");
    json_print_escaped(e->filename, strnlen(e->filename, sizeof(e->filename)));
    printf("\",");
    printf("\"parent\":\"");
    json_print_escaped(e->parent, strnlen(e->parent, sizeof(e->parent)));
    printf("\",");
    printf("\"head_len\":%u,", e->head_len);
    printf("\"tail_len\":%u,", e->tail_len);
    printf("\"head\":\"");
    json_print_escaped(e->head, e->head_len);
    printf("\",");
    printf("\"tail\":\"");
    json_print_escaped(e->tail, e->tail_len);
    printf("\"");
    printf("}\n");
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    int err;

    argp_parse(&argp, argc, argv, 0, NULL, NULL);

    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rlim);
    setrlimit(RLIMIT_STACK, &rlim);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = memwrite_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open memwrite BPF skeleton\n");
        return 1;
    }

    /* Set the watch prefixes into .rodata before loading.
     * --prefix accepts comma-separated list (up to MAX_WATCH_PREFIXES). */
    char prefixes[MAX_WATCH_PREFIXES][WATCH_PREFIX_LEN];
    int nprefixes = 0;
    char *copy = strdup(prefix);
    char *saveptr = NULL;
    for (char *tok = strtok_r(copy, ",", &saveptr);
         tok != NULL && nprefixes < MAX_WATCH_PREFIXES;
         tok = strtok_r(NULL, ",", &saveptr)) {
        if (*tok == '\0')
            continue;
        size_t tlen = strlen(tok);
        if (tlen >= WATCH_PREFIX_LEN)
            tlen = WATCH_PREFIX_LEN - 1;
        memset(prefixes[nprefixes], 0, WATCH_PREFIX_LEN);
        memcpy(prefixes[nprefixes], tok, tlen);
        nprefixes++;
    }
    free(copy);
    if (nprefixes == 0) {
        /* default fallback: ehragent_memory */
        size_t dlen = strlen("ehragent_memory");
        memset(prefixes[0], 0, WATCH_PREFIX_LEN);
        memcpy(prefixes[0], "ehragent_memory", dlen);
        nprefixes = 1;
    }
    memset((char *)skel->rodata->watch_prefix, 0,
           sizeof(skel->rodata->watch_prefix));
    for (int i = 0; i < nprefixes; i++)
        memcpy((char *)skel->rodata->watch_prefix[i], prefixes[i],
               WATCH_PREFIX_LEN);
    skel->rodata->watch_prefix_count = nprefixes;

    err = memwrite_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load memwrite BPF program: %d\n", err);
        goto cleanup;
    }

    err = memwrite_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach memwrite probes: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    fprintf(stderr, "memwrite: watching %d prefixes (\"%s\") (Ctrl+C to stop)\n",
            nprefixes, prefix);

    while (!stop) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR)
            continue;
        if (err < 0) {
            fprintf(stderr, "ring buffer poll error: %d\n", err);
            break;
        }
    }

cleanup:
    if (rb)
        ring_buffer__free(rb);
    if (skel)
        memwrite_bpf__destroy(skel);
    return err;
}