// socket_connect.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define EPERM 1
#define MAX_PATH_LEN 256
#define NUM_PATHS 2


const char restricted_paths[][MAX_PATH_LEN] = {
    "/etc/inetd.conf",
    "/etc/inetd.d",
};

const char telnet_service_exec[] = "/usr/sbin/inetutils-inetd";

SEC("lsm.s/bprm_check_security")
int BPF_PROG(deny_bprm_check, struct linux_binprm *bprm)
{

    char buf[MAX_PATH_LEN] = {};
    struct file *file;
    if (!bprm)
        return 0;

    if (bpf_core_read_str(buf, sizeof(buf), bprm->filename) < 0)
        return 0;

    // bpf_printk("lsm: denying execute of %s", buf);
    if (__builtin_memcmp(buf, telnet_service_exec, sizeof(telnet_service_exec) - 1) == 0)
        return -EPERM;

    return 0;
}

SEC("lsm.s/file_open")
int BPF_PROG(deny_file_open, struct file *file)
{
    char buf[MAX_PATH_LEN] = {};

    if (!file)
        return 0;

    if (bpf_d_path(&file->f_path, buf, sizeof(buf)) < 0)
        return 0;

    #pragma unroll
    for (int i = 0; i < NUM_PATHS; i++) {
        if (__builtin_memcmp(buf, restricted_paths[i], __builtin_strlen(restricted_paths[i])) == 0) {
            bpf_printk("lsm: denying open of %s", buf);
            return -EPERM;
        }
    }

    // Default: allow
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
