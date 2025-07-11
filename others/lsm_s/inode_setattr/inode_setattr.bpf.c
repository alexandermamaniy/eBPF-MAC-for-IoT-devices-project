#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define EPERM 1
#define MAX_PATH_LEN 256
#define ATTR_MODE    (1 << 0)

char LICENSE[] SEC("license") = "GPL";
const char target_path[] = "prohibido.txt";

// Block chmod on a specific file by triggering inode_setattr LSM hook
SEC("lsm.s/inode_setattr")
int BPF_PROG(deny_chmod_by_path ,struct dentry *dentry, struct iattr *attr) {

    if (!dentry || !attr)
        return 0;

    if (!(attr->ia_valid & ATTR_MODE))
        return 0;

    struct qstr d_name = BPF_CORE_READ(dentry, d_name);
    char buf[32];
    bpf_core_read_str(buf, sizeof(buf), d_name.name);

    if (__builtin_memcmp(buf, target_path, sizeof(target_path) - 1) == 0) {
        bpf_printk("Blocking chmod on %s\n", buf);
        return -EPERM;
    }
    return 0;
}