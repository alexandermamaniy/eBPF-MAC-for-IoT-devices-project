#!/usr/bin/python3

from bcc import BPF

bpf_source = """

#include <linux/sched.h>

BPF_PERF_OUTPUT(events);

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};

struct sys_enter_openat_args_t {
    // see /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
    uint64_t _unused;

    u32 _nr;
    u64 dfd;
    char *filename;
    u64 flags;
    u64 mode;
};

int sys_enter_openat_fn(struct sys_enter_openat_args_t *args){
    struct data_t data = {};

    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_trace_printk("openat has fired %d \\n", pid);

    data.pid = pid;
    bpf_probe_read_str(data.comm, TASK_COMM_LEN, args->filename);

    events.perf_submit(args, &data, sizeof(data));
    return 0;
};
"""

bpf = BPF(text=bpf_source)
bpf.attach_tracepoint(tp="syscalls:sys_enter_openat", fn_name="sys_enter_openat_fn")

def handle_sys_enter_openat(cpu, data, size):
    event = bpf["events"].event(data)
    pid = event.pid
    comm = event.comm

    print("the pid is: ", pid, " the comm is ", comm)

bpf["events"].open_perf_buffer(handle_sys_enter_openat)

while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

