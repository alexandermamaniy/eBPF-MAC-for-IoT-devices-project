#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define EPERM 1
#define MAX_PATH_LEN 256


const char telnet_exec[] = "/usr/bin/telnet";

// LSM hook that denies execution of telnet client
SEC("lsm.s/bprm_check_security")
int BPF_PROG(deny_bprm_check, struct linux_binprm *bprm)
{

    char buf[MAX_PATH_LEN] = {};
    struct file *file;
    if (!bprm)
        return 0;
    if (bpf_core_read_str(buf, sizeof(buf), bprm->filename) < 0)
        return 0;


    if (__builtin_memcmp(buf, telnet_exec, sizeof(telnet_exec) - 1) == 0) {
    	bpf_printk("bprm_check_security: denying execution of %s", buf);
		return -EPERM;
	}

    return 0;
}

char LICENSE[] SEC("license") = "GPL";