from bcc import BPF
from kubernetes import client, config
import time

# 1. Load Kubernetes configuration
config.load_kube_config()
v1 = client.CoreV1Api()

# 2. eBPF Program to trace SIGTERM signals
ebpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(counter, u32, u64);

int trace_kill(struct pt_regs *ctx, int pid, int sig) {
    if (sig == SIGTERM) { // Check for SIGTERM signal
        u32 tgid = bpf_get_current_pid_tgid() >> 32; // Get PID
        u64 *val, one = 1;

        val = counter.lookup_or_init(&tgid, &one);
        if (val) {
            (*val)++;
        }
    }
    return 0;
}
"""

# 3. Load eBPF program
bpf = BPF(text=ebpf_program)
bpf.attach_kprobe(event="sys_kill", fn_name="trace_kill")
print("Tracing SIGTERM syscalls... Press Ctrl+C to stop.")

# 4. Function to map PID to Pod
def get_pod_by_pid(pid):
    for pod in v1.list_pod_for_all_namespaces().items:
        try:
            pod_namespace = pod.metadata.namespace
            pod_name = pod.metadata.name
            # Fetch PID from Pod's /proc (example requires extra tools or PID mapping logic)
            if str(pid) in pod_name:  # Simplified mapping for demo purposes
                return f"{pod_namespace}/{pod_name}"
        except Exception:
            pass
    return "Unknown Pod"

# 5. Monitor syscalls and map them to Pods
try:
    while True:
        print("=== Syscall Data ===")
        for pid, count in bpf["counter"].items():
            pod_name = get_pod_by_pid(pid.value)
            print(f"Pod: {pod_name}, PID: {pid.value}, SIGTERM Count: {count.value}")
        time.sleep(2)
except KeyboardInterrupt:
    print("Exiting...")