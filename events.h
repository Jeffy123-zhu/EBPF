// events.h
// Event structure definitions for eBPF Time Machine
// 
// Version history:
// v0.1 (Nov 16) - Basic structure
// v0.2 (Nov 17) - Added memory tracking
// v0.3 (Nov 18) - Added network events
// v0.4 (Nov 19) - Current version with full context

#ifndef __EVENTS_H
#define __EVENTS_H

#include <linux/types.h>

// Event type definitions
// Started with just 3, added more as needed
enum event_type {
    EVENT_FUNC_ENTRY = 1,
    EVENT_FUNC_EXIT = 2,
    EVENT_ALLOC = 3,      // malloc, calloc, realloc
    EVENT_FREE = 4,
    EVENT_SYSCALL = 5,
    EVENT_NET_TX = 6,
    EVENT_NET_RX = 7,
    EVENT_FILE_OP = 8,
    EVENT_SIGNAL = 9,     // crash detection
    EVENT_THREAD = 10,    // pthread ops
};

// Main event structure
// NOTE: Keep this under 256 bytes for efficiency
// FIXME: might want to split into smaller events later
struct event_data {
    // Header (24 bytes)
    __u64 timestamp;        // nanoseconds since boot
    __u32 pid;
    __u32 tid;
    __u16 type;
    __u16 cpu_id;
    __u32 flags;
    
    // Context info (32 bytes)
    __u64 ip;               // instruction pointer
    __u64 sp;               // stack pointer  
    __u64 bp;               // base pointer
    __u64 return_addr;      // for function calls
    
    // Event-specific data (64 bytes)
    // Using union to save space
    union {
        // Function call info
        struct {
            __u64 func_addr;
            __u64 args[6];      // first 6 args (x86_64 abi)
            __u64 retval;
        } func;
        
        // Memory allocation
        struct {
            __u64 addr;
            __u64 size;
            __u64 old_addr;     // for realloc
            __u32 flags;
            __u32 callsite;     // where was it called from
        } mem;
        
        // System call
        struct {
            __u32 nr;           // syscall number
            __u32 pad;
            __u64 args[6];
            __s64 ret;
        } syscall;
        
        // Network event
        struct {
            __u32 saddr;
            __u32 daddr;
            __u16 sport;
            __u16 dport;
            __u32 len;
            __u16 proto;
            __u16 pad;
        } net;
        
        // File operation
        struct {
            __u32 fd;
            __u32 flags;
            __u64 offset;
            __u64 len;
            char path[40];      // partial path
        } file;
        
        // Signal/crash
        struct {
            __u32 signal;
            __u32 code;
            __u64 fault_addr;
            char info[48];
        } sig;
    } data;
    
    // Stack trace ID (optional)
    __s32 stack_id;
    __u32 _pad2;
};

// BPF maps

// Main ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 * 1024);  // 256MB
} events SEC(".maps");

// Track which PIDs to monitor
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u8);
} tracked_pids SEC(".maps");

// Stack traces
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 10000);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 127 * sizeof(__u64));
} stack_traces SEC(".maps");

// Active allocations tracking (for leak detection)
struct alloc_info {
    __u64 size;
    __u64 timestamp;
    __s32 stack_id;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);  // track up to 100k allocations
    __type(key, __u64);           // address
    __type(value, struct alloc_info);
} active_allocs SEC(".maps");

// Per-CPU scratch space to avoid stack overflow
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event_data);
} scratch_event SEC(".maps");

// Helper: check if we should trace this PID
static __always_inline int should_trace(void) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 *tracked = bpf_map_lookup_elem(&tracked_pids, &pid);
    return tracked && *tracked;
}

// Helper: get scratch event buffer
static __always_inline struct event_data* get_event_buf(void) {
    __u32 zero = 0;
    return bpf_map_lookup_elem(&scratch_event, &zero);
}

// Helper: submit event to userspace
static __always_inline void submit_event(struct event_data *evt) {
    bpf_ringbuf_output(&events, evt, sizeof(*evt), 0);
}

// Helper: fill common fields
static __always_inline void fill_common_fields(struct event_data *evt, __u16 type) {
    evt->timestamp = bpf_ktime_get_ns();
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    evt->type = type;
    evt->cpu_id = bpf_get_smp_processor_id();
}

#endif // __EVENTS_H
