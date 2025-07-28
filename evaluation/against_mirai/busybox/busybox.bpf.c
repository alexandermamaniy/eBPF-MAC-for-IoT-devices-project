
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_PATH_LEN 256
#define MAX_ARG_LEN 128
#define MAX_ARGS 5

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SSEC("kprobe/__x64_sys_execve")
int capture_execve(struct pt_regs *ctx)
{
    char path[MAX_PATH_LEN] = {};
    char arg[MAX_ARG_LEN] = {};

    const char *filename = (const char *)PT_REGS_PARM1(ctx);
    const char *const *argv = (const char *const *)PT_REGS_PARM2(ctx);

    bpf_probe_read_user_str(path, sizeof(path), filename);
    bpf_printk("Exec path: %s\n", path);

#pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
        if (!argp)
            break;
        bpf_probe_read_user_str(arg, sizeof(arg), argp);
        bpf_printk("argv[%d]: %s\n", i, arg);
    }

    return 0;
}

/*
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
    pid_t pid;
    const char *filename;

    pid = bpf_get_current_pid_tgid() >> 32;
    filename = BPF_CORE_READ(name, name);
    bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
    return 0;
}


SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret)
{
    pid_t pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);
    return 0;
}
*/

