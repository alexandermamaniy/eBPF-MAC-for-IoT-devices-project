// test_lsm.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/dentry.h>

SEC("lsm/inode_removexattr")
int BPF_PROG(test_inode_removexattr, struct dentry *dentry)
{
    // You can add debug logic here if needed
    return 0; // Always allow
}

char LICENSE[] SEC("license") = "GPL";