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


// lsm-connect.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1
#define AF_INET 2

// Define allowed IPv4 addresses (in network byte order)
const __u32 allowed_ips[] = {
    0x01010101, // 1.1.1.1
    0x08080808, // 8.8.8.8
    // Add more as needed
};
const int allowed_ips_count = sizeof(allowed_ips) / sizeof(allowed_ips[0]);

SEC("lsm/socket_connect")
int BPF_PROG(restrict_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    if (ret != 0)
        return ret;

    if (address->sa_family != AF_INET)
        return 0;

    struct sockaddr_in *addr = (struct sockaddr_in *)address;
    __u32 dest = addr->sin_addr.s_addr;

    // Check if dest is in allowed_ips
    int allowed = 0;
    for (int i = 0; i < allowed_ips_count; i++) {
        if (dest == allowed_ips[i]) {
            allowed = 1;
            break;
        }
    }

    if (!allowed) {
        bpf_printk("lsm: blocking %d", dest);
        return -EPERM;
    }

    bpf_printk("lsm: allowed %d", dest);
    return 0;
}