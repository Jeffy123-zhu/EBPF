// tracer.bpf.c
// eBPF programs for Time Machine - comprehensive system tracing
// 
// Development history:
// v0.1 (Nov 16) - Basic uprobe
// v0.2 (Nov 17) - Added malloc/free  
// v0.3 (Nov 18) - Signal handling
// v0.4 (Nov 19) - Current version

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "events.h"

char LICENSE[] SEC("license") = "GPL";

// ============================================================================
// FUNCTION TRACING
// ============================================================================

SEC("uprobe/func")
int trace_func_enter(struct pt_regs *ctx) {
    if (!should_trace())
        return 0;
    
    struct event_data *evt = get_event_buf();
    if (!evt)
        return 0;
    
    fill_common_fields(evt, EVENT_FUNC_ENTRY);
    
    evt->ip = PT_REGS_IP(ctx);
    evt->sp = PT_REGS_SP(ctx);
    evt->bp = PT_REGS_FP(ctx);
    
    // Capture arguments (x86_64 calling convention)
    evt->data.func.func_addr = evt->ip;
    evt->data.func.args[0] = PT_REGS_PARM1(ctx);
    evt->data.func.args[1] = PT_REGS_PARM2(ctx);
    evt->data.func.args[2] = PT_REGS_PARM3(ctx);
    evt->data.func.args[3] = PT_REGS_PARM4(ctx);
    evt->data.func.args[4] = PT_REGS_PARM5(ctx);
    evt->data.func.args[5] = PT_REGS_PARM6(ctx);
    
    // Get stack trace
    evt->stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    
    submit_event(evt);
    return 0;
}

SEC("uretprobe/func")
int trace_func_exit(struct pt_regs *ctx) {
    if (!should_trace())
        return 0;
    
    struct event_data *evt = get_event_buf();
    if (!evt)
        return 0;
    
    fill_common_fields(evt, EVENT_FUNC_EXIT);
    evt->ip = PT_REGS_IP(ctx);
    evt->data.func.func_addr = evt->ip;
    evt->data.func.retval = PT_REGS_RC(ctx);
    
    submit_event(evt);
    return 0;
}

// ============================================================================
// MEMORY TRACING
// ============================================================================

SEC("uprobe/malloc")
int trace_malloc_enter(struct pt_regs *ctx) {
    if (!should_trace())
        return 0;
    
    struct event_data *evt = get_event_buf();
    if (!evt)
        return 0;
    
    fill_common_fields(evt, EVENT_ALLOC);
    evt->ip = PT_REGS_IP(ctx);
    evt->data.mem.size = PT_REGS_PARM1(ctx);
    
    submit_event(evt);
    return 0;
}

SEC("uretprobe/malloc")
int trace_malloc_exit(struct pt_regs *ctx) {
    if (!should_trace())
        return 0;
    
    __u64 addr = PT_REGS_RC(ctx);
    if (addr == 0)
        return 0;
    
    struct event_data *evt = get_event_buf();
    if (!evt)
        return 0;
    
    fill_common_fields(evt, EVENT_ALLOC);
    evt->data.mem.addr = addr;
    evt->stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    
    // Track active allocation
    struct alloc_info info = {
        .size = 0,
        .timestamp = evt->timestamp,
        .stack_id = evt->stack_id,
    };
    bpf_map_update_elem(&active_allocs, &addr, &info, BPF_ANY);
    
    submit_event(evt);
    return 0;
}

SEC("uprobe/calloc")
int trace_calloc_enter(struct pt_regs *ctx) {
    if (!should_trace())
        return 0;
    
    struct event_data *evt = get_event_buf();
    if (!evt)
        return 0;
    
    fill_common_fields(evt, EVENT_ALLOC);
    
    __u64 nmemb = PT_REGS_PARM1(ctx);
    __u64 size = PT_REGS_PARM2(ctx);
    evt->data.mem.size = nmemb * size;
    evt->data.mem.flags = 1; // calloc flag
    
    submit_event(evt);
    return 0;
}

SEC("uretprobe/calloc")
int trace_calloc_exit(struct pt_regs *ctx) {
    return trace_malloc_exit(ctx);
}

SEC("uprobe/free")
int trace_free(struct pt_regs *ctx) {
    if (!should_trace())
        return 0;
    
    __u64 addr = PT_REGS_PARM1(ctx);
    if (addr == 0)
        return 0;
    
    struct event_data *evt = get_event_buf();
    if (!evt)
        return 0;
    
    fill_common_fields(evt, EVENT_FREE);
    evt->data.mem.addr = addr;
    evt->ip = PT_REGS_IP(ctx);
    evt->stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    
    // Remove from tracking
    bpf_map_delete_elem(&active_allocs, &addr);
    
    submit_event(evt);
    return 0;
}

// ============================================================================
// SIGNAL HANDLING (Crash Detection)
// ============================================================================

SEC("tracepoint/signal/signal_deliver")
int trace_signal(void *ctx) {
    if (!should_trace())
        return 0;
    
    // Read signal info from tracepoint context
    int sig;
    bpf_probe_read(&sig, sizeof(sig), ctx + 16); // offset may vary
    
    // Only fatal signals
    if (sig != 11 && sig != 6 && sig != 4 && sig != 8)
        return 0;
    
    struct event_data *evt = get_event_buf();
    if (!evt)
        return 0;
    
    fill_common_fields(evt, EVENT_SIGNAL);
    evt->data.sig.signal = sig;
    
    const char *sig_name = "CRASH";
    if (sig == 11) sig_name = "SIGSEGV";
    else if (sig == 6) sig_name = "SIGABRT";
    else if (sig == 4) sig_name = "SIGILL";
    else if (sig == 8) sig_name = "SIGFPE";
    
    __builtin_memcpy(evt->data.sig.info, sig_name, 
                     sizeof(evt->data.sig.info));
    
    submit_event(evt);
    return 0;
}

// ============================================================================
// SYSTEM CALLS (Basic)
// ============================================================================

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(void *ctx) {
    if (!should_trace())
        return 0;
    
    struct event_data *evt = get_event_buf();
    if (!evt)
        return 0;
    
    fill_common_fields(evt, EVENT_SYSCALL);
    
    // Read syscall number and args from context
    __u64 id;
    bpf_probe_read(&id, sizeof(id), ctx + 8);
    evt->data.syscall.nr = id;
    
    submit_event(evt);
    return 0;
}

// ============================================================================
// FILE OPERATIONS
// ============================================================================

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(void *ctx) {
    if (!should_trace())
        return 0;
    
    struct event_data *evt = get_event_buf();
    if (!evt)
        return 0;
    
    fill_common_fields(evt, EVENT_FILE_OP);
    
    // Read filename pointer from context
    const char *filename;
    bpf_probe_read(&filename, sizeof(filename), ctx + 24);
    bpf_probe_read_user_str(evt->data.file.path, 
                           sizeof(evt->data.file.path),
                           filename);
    
    submit_event(evt);
    return 0;
}
