#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// #define TASK_COMM_LEN 16
#define EPERM 1
#define MAX_PATH_LEN 256

char LICENSE[] SEC("license") = "GPL";

const char mirai_exec[] = "/tmp/mirai";

// Block execution of /tmp/mirai by trigger bprm_check_security LSM hook
SEC("lsm.s/bprm_check_security")
int BPF_PROG(deny_bprm_check, struct linux_binprm *bprm)
{

    char buf[MAX_PATH_LEN] = {};
    struct file *file;
    if (!bprm)
        return 0;

    if (bpf_core_read_str(buf, sizeof(buf), bprm->filename) < 0)
        return 0;

    bpf_printk("lsm: denying open of %s", buf);
    if (__builtin_memcmp(buf, mirai_exec, sizeof(mirai_exec) - 1) == 0)
        return -EPERM;

    return 0;
}
