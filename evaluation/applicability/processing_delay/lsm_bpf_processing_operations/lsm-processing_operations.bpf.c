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
// Create file operations
SEC("lsm/inode_create")
int BPF_PROG(on_create, struct inode *dir, struct dentry *dentry, umode_t mode) {
    // char name[MAX_NAME_LEN] = {};
    // bpf_core_read_str(name, sizeof(name), dentry->d_name.name);
    // bpf_printk("lsm: create %s\n", name);
    count_op();
    return 0;
}
// delete file operations
SEC("lsm/inode_unlink")
int BPF_PROG(on_unlink, struct inode *dir, struct dentry *dentry) {
    // char name[MAX_NAME_LEN] = {};
    // bpf_core_read_str(name, sizeof(name), dentry->d_name.name);
    // bpf_printk("lsm: unlink %s\n", name);
    count_op();
    return 0;
}

// create directory operations
SEC("lsm/inode_mkdir")
int BPF_PROG(on_mkdir, struct inode *dir, struct dentry *dentry, umode_t mode) {
    // char name[MAX_NAME_LEN] = {};
    // bpf_core_read_str(name, sizeof(name), dentry->d_name.name);
    // bpf_printk("lsm: mkdir %s\n", name);

    count_op();
    return 0;
}

// delete directory operations
SEC("lsm/inode_rmdir")
int BPF_PROG(on_rmdir, struct inode *dir, struct dentry *dentry) {
    //char name[MAX_NAME_LEN] = {};
    //bpf_core_read_str(name, sizeof(name), dentry->d_name.name);
    //bpf_printk("lsm: rmdir %s\n", name);
    count_op();
    return 0;
}

// read and write operations
SEC("lsm/file_permission")
int BPF_PROG(on_file_permission, struct file *file, int mask) {
    bpf_printk("lsm: file_permission event (mask=%d)\n", mask);
    count_op();
    return 0;
}

// No supported due to kernel version

// read operations
// SEC("lsm/file_read")
// int BPF_PROG(on_file_read, struct file *file) {
//     bpf_printk("lsm: file_read event\n");
//     count_op();
//     return 0;
// }

// No supported due to kernel version
// write operations
// SEC("lsm/file_write")
// int BPF_PROG(on_file_write, struct file *file) {
//     bpf_printk("lsm: file_write event\n");
//     count_op();
//     return 0;
// }

// Very expensive operations
// stat and open
// SEC("lsm/inode_permission")
// int BPF_PROG(on_inode_permission, struct inode *inode, int mask) {
//    bpf_printk("lsm: inode_permission event (mask=%d)\n", mask);
//    count_op();
//    return 0;
// }
