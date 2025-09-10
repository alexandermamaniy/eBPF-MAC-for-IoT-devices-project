#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";
#define MAX_NAME_LEN 64
#define MAX_PATH_LEN 256


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} lsm_op_count SEC(".maps");

static __always_inline void count_op() {
    u32 key = 0;
    u64 *val = bpf_map_lookup_elem(&lsm_op_count, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
}


SEC("lsm.s/file_open")
int BPF_PROG(mark_wget_inodes, struct file *file, int flags)
{
   //	count_op();
//	bpf_printk("file_open: this hook have been triggered");
    return 0;
}

// bprm_check_security: block execution of marked inodes
SEC("lsm.s/bprm_check_security")
int BPF_PROG(block_marked_exec, struct linux_binprm *bprm)
{
  //  count_op();
//	bpf_printk("bprm_check_security: this hook have been triggered" );
    return 0;
}


// Block chmod on marked inodes (created by wget)


SEC("lsm.s/inode_setattr")
int BPF_PROG(block_marked_chmod, struct dentry *dentry, struct iattr *attr)
{
  //  count_op();
//	bpf_printk("inode_setattr: this hook have been triggered");
    return 0;
}

SEC("lsm.s/socket_connect")
int BPF_PROG(block_telnet_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
//	count_op();
//	bpf_printk("inode_setattr: this hook have been triggered");
    return 0;
}

