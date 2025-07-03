#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define EPERM 1
#define MAX_PATH_LEN 256

char LICENSE[] SEC("license") = "GPL";

const char target_path[] = "/usr/bin/wget";

SEC("lsm.s/file_open")
int BPF_PROG(deny_file_open, struct file *file)
{
    char buf[MAX_PATH_LEN] = {};
    char comm[TASK_COMM_LEN] = {};
    char parent_comm[TASK_COMM_LEN] = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = NULL;
    const char *parent_comm_ptr = NULL;

    if (!file)
        return 0;

    if (bpf_d_path(&file->f_path, buf, sizeof(buf)) < 0)
        return 0;

    if (__builtin_memcmp(buf, target_path, sizeof(target_path) - 1) != 0)
        return 0;

    bpf_get_current_comm(comm, sizeof(comm));
    parent = BPF_CORE_READ(task, real_parent);
    if (parent) {
        parent_comm_ptr = BPF_CORE_READ(parent, comm);
        bpf_core_read_str(&parent_comm, sizeof(parent_comm), parent_comm_ptr);
    }

    if (__builtin_memcmp(parent_comm, "inetd", 7) == 0) {
        bpf_printk("lsm: wget open denied from telnetd session: %s", buf);
        return -EPERM;
    }

    bpf_printk("lsm: denying open of %s", buf);
    return -EPERM;
}