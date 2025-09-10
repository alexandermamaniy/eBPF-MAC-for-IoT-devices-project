#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1
#define AF_INET 2

// Define the allowed IPs of DNS server and allowed server
const __u32 allowed_ips[] = {
    __builtin_bswap32(0x96320096), // 150.50.0.150
    __builtin_bswap32(0x96003296), // 150.0.50.150

    __builtin_bswap32(0x96320066), // 150.50.0.102
    __builtin_bswap32(0x66003296), // 102.0.50.150
};
const int allowed_ips_count = sizeof(allowed_ips) / sizeof(allowed_ips[0]);

// Restrict socket connections to specific IPs
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
    __u32 dest_host = __builtin_bswap32(dest);
    for (int i = 0; i < allowed_ips_count; i++) {
        if (dest_host == allowed_ips[i]) {
            allowed = 1;
            break;
        }
    }
    if (!allowed) {
        __u8 *bytes = (__u8 *)&dest;
        bpf_printk("socket_connect: blocking connection to %d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);

        return -EPERM;
    }

    __u8 *bytes = (__u8 *)&dest;
    bpf_printk("socket_connect: found connect to %d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
    return 0;
}