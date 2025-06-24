// lsm-file-open.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <linux/limits.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1

const char target_path[] = "/home/vagrant/shared/file_open_s/file.xtx";

// Use a smaller buffer to fit in the eBPF stack
#define MAX_PATH_LEN 256

SEC("lsm.s/file_open")
int BPF_PROG(deny_file_open, struct file *file)
{
    char fname[MAX_PATH_LEN];

    if (bpf_d_path(&file->f_path, fname, sizeof(fname)) < 0)
        return 0;

    if (__builtin_memcmp(fname, target_path, sizeof(target_path) - 1) == 0) {
        bpf_printk("lsm: denying open of %s", fname);
        return -EPERM;
    }
    return 0;
}