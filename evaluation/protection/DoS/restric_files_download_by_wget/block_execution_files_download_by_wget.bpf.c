#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define EPERM 1
#define MAX_COMM 16
#define O_CREAT 0100

// Map to store marked inodes created by wget
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);      // inode number
    __type(value, u8);     // marker
    __uint(max_entries, 1024);
} marked_inodes SEC(".maps");

// file_open: mark inodes created by wget
SEC("lsm.s/file_open")
int BPF_PROG(mark_wget_inodes, struct file *file, int flags)
{
    char comm[MAX_COMM] = {};
    u64 ino;
    u8 one = 1;

    bpf_get_current_comm(&comm, sizeof(comm));

    if (!(comm[0] == 'w' && comm[1] == 'g' && comm[2] == 'e' && comm[3] == 't' &&
          (comm[4] == '\0' || (comm[4] < '0' || (comm[4] > '9' && comm[4] < 'A') || (comm[4] > 'Z' && comm[4] < 'a') || comm[4] > 'z')))) {
        return 0;
    }

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode){
        return 0;
    }

    ino = BPF_CORE_READ(inode, i_ino);

    bpf_map_update_elem(&marked_inodes, &ino, &one, BPF_ANY);
    bpf_printk("file_open: Marked inode %llu as created by %s\n", ino, comm);
    return 0;
}

// bprm_check_security: block execution of marked inodes
SEC("lsm.s/bprm_check_security")
int BPF_PROG(block_marked_exec, struct linux_binprm *bprm)
{
    struct file *file = BPF_CORE_READ(bprm, file);
    if (!file)
        return 0;

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    u64 ino = BPF_CORE_READ(inode, i_ino);
    u8 *found = bpf_map_lookup_elem(&marked_inodes, &ino);
    if (found) {
        bpf_printk("bprm_check_security: Blocking execution of inode %llu (wget)\n", ino);
        return -EPERM;
    }
    return 0;
}


// Block chmod on marked inodes (created by wget)
SEC("lsm.s/inode_setattr")
int BPF_PROG(block_marked_chmod, struct dentry *dentry, struct iattr *attr)
{
    if (!dentry || !attr)
        return 0;

    if (!(attr->ia_valid & (1 << 0)))
        return 0;

    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode)
        return 0;

    u64 ino = BPF_CORE_READ(inode, i_ino);
    u8 *found = bpf_map_lookup_elem(&marked_inodes, &ino);
    if (found) {
        bpf_printk("inode_setattr: Blocking chmod on inode %llu (wget)\n", ino);
        return -EPERM;
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
