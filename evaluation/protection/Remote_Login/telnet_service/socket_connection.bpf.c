#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define EPERM 1
#define MAX_PATH_LEN 256
#define NUM_PATHS 2
#define AF_INET 2

// Define the paths of restricted configuration files of telnet service
const char restricted_paths[][MAX_PATH_LEN] = {
    "/etc/inetd.conf",
    "/etc/inetd.d",
};

// Define the telnet service executable path
const char telnet_service_exec[] = "/usr/sbin/inetutils-inetd";

// LSM hook that denies execution of telnet service
SEC("lsm.s/bprm_check_security")
int BPF_PROG(deny_bprm_check, struct linux_binprm *bprm)
{

    char buf[MAX_PATH_LEN] = {};
    struct file *file;
    if (!bprm)
        return 0;

    if (bpf_core_read_str(buf, sizeof(buf), bprm->filename) < 0)
        return 0;

    if (__builtin_memcmp(buf, telnet_service_exec, sizeof(telnet_service_exec) - 1) == 0){
        bpf_printk("bprm_check_security: denying execute of %s", buf);
        return -EPERM;
    }


    return 0;
}

// LSM hook that denies file open operations on restricted config file paths
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
            bpf_printk("file_open: denying open of %s", buf);
            return -EPERM;
        }
    }
    return 0;
}


// LSM hook that blocks telnet connections on port 23
SEC("lsm.s/socket_connect")
int BPF_PROG(block_telnet_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    struct sockaddr_in *addr = (struct sockaddr_in *)address;
    if (addr->sin_family == AF_INET) {

        // Convert port from network to host byte order
        if (__builtin_bswap16(addr->sin_port) == 23) {
            bpf_printk("socket_connect: Blocking connection in port 23 \n");
            return -EPERM;
        }
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
