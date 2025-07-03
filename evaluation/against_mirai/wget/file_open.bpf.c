// lsm-file-open.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define MAX_PATH_LEN 256
#define EPERM 1

char LICENSE[] SEC("license") = "GPL";
const char target_path[] = "/usr/bin/wget";

// Block file open on a specific path by triggering file_open LSM hook
SEC("lsm.s/file_open")
int BPF_PROG(deny_file_open, struct file *file)
{
    char buf[MAX_PATH_LEN] = {};

    if (!file)
        return 0;

    if (bpf_d_path(&file->f_path, buf, sizeof(buf)) < 0)
        return 0;

    if (__builtin_memcmp(buf, target_path, sizeof(target_path) - 1) == 0) {
        bpf_printk("lsm: denying open of %s", buf);
        return -EPERM;
    }

    return 0;
}