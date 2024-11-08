#define __TARGET_ARCH_x86
#define MSG_SIZE 128

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct event {
    __u32 pid;          // Process ID
    char comm[16];      // Command name (process name)
    char filename[256]; // Filename being deleted
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); // Type of BPF map
    __uint(max_entries, 1024);                   // Maximum number of entries in the map
    __type(key, int);                            // Type of the key
    __type(value, int);                          // Type of the value
} events SEC(".maps");                            // Place the map in the "maps" section

// Tracepoint for the sys_enter_unlinkat syscall
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter* ctx) {
    struct event evt = {}; // Initialize an event structure

    // Get the current process ID
    evt.pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_user_str(&evt.filename, sizeof(evt.filename), (void *)(ctx->args[1]));
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

    return 0;
}

char _license[] SEC("license") = "GPL";