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

// ===============================  No used for now===============================
//SEC("lsm/inode_rename")
//int BPF_PROG(on_rename, struct inode *old_dir, struct dentry *old_dentry,
//             struct inode *new_dir, struct dentry *new_dentry, unsigned int flags) {
//    char old_name[MAX_NAME_LEN] = {};
//    char new_name[MAX_NAME_LEN] = {};
//    bpf_core_read_str(old_name, sizeof(old_name), old_dentry->d_name.name);
//    bpf_core_read_str(new_name, sizeof(new_name), new_dentry->d_name.name);
//    bpf_printk("lsm: rename %s -> %s\n", old_name, new_name);
//    count_op();
//    return 0;
//}

//SEC("lsm/file_open")
//int BPF_PROG(on_file_open, struct file *file) {
//    char buf[MAX_PATH_LEN] = {};
//    if (bpf_d_path(&file->f_path, buf, sizeof(buf)) == 0)
//        bpf_printk("lsm: open %s\n", buf);
//    count_op();
//    return 0;
//}