#!/usr/bin/python
from bcc import BPF
from time import sleep

# eBPF Program
bpf = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(counter, u32, u64);
BPF_HASH(debug, u32, u64); // Debug counter

int trace_kill(struct pt_regs *ctx, int pid, int sig) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32; // PID
    u64 *val, one = 1;

    // Debug: ดูว่าฟังก์ชันถูกเรียกหรือไม่
    bpf_trace_printk("Signal=%d for PID=%d\\n", sig, tgid);

    // Debug Counter
    val = debug.lookup_or_init(&tgid, &one);
    if (val) {
        (*val)++;
    }

    // จับเฉพาะ SIGKILL(9) or SIGTERM(15)
    if (sig == SIGKILL) {
        val = counter.lookup_or_init(&tgid, &one);
        if (val) {
            (*val)++;
        }
    }
    return 0;
}
""")

# Attach to syscall
syscall = bpf.b.get_syscall_prefix().decode() + 'kill'
bpf.attach_kprobe(event=syscall, fn_name="trace_kill")

print("Tracing SIGKILL... Press Ctrl+C to stop.")
try:
    while True:
        # Print Debug Counter
        print("\n=== Debug Data ===")
        for k, v in bpf["debug"].items():
            print(f"PID {k.value} invoked trace_kill: {v.value} times")
        sleep(1)
        # Print SIGKILL Counter
        print("\n=== KILL Data ===")
        for k, v in bpf["counter"].items():
            print(f"PID {k.value}: {v.value} SIGKILL signals")
        
except KeyboardInterrupt:
    print("Exiting...")
