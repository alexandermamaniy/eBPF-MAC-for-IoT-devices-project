// socket_connect.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define EPERM 1
#define MAX_PATH_LEN 256
// #define AF_INET 2


const char telnet_exec[] = "/usr/bin/telnet";

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
    if (__builtin_memcmp(buf, telnet_exec, sizeof(telnet_exec) - 1) == 0)
        return -EPERM;

    return 0;
}


/*
SEC("lsm.s/socket_connect")
int BPF_PROG(block_telnet_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    struct sockaddr_in *addr = (struct sockaddr_in *)address;
    if (addr->sin_family == AF_INET) {
        // Convert port from network to host byte order
        if (__builtin_bswap16(addr->sin_port) == 23) {
            bpf_printk("Blocking Telnet connection\n");
            return -EPERM;
        }
    }
    return 0;
}
*/
char LICENSE[] SEC("license") = "GPL";