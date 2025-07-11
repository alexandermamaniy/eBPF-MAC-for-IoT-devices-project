#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define EPERM 1
#define MAX_PATH_LEN 256
#define MAX_PATH_DEPTH 32
#define MAX_DNAME_LEN 256

struct path_data {
    char buf[MAX_PATH_LEN];
    int truncated;
};

static __always_inline size_t read_path_data(struct path *path, struct path_data *pd) {
    u8 slash = '/';
    u8 zero = 0;
    u32 buf_off = (MAX_PATH_LEN >> 1);
    unsigned int len, off;
    int sz;

    struct path f_path;
    bpf_probe_read(&f_path, sizeof(f_path), path);
    struct dentry *dentry = f_path.dentry;
    struct dentry *d_parent;
    struct qstr d_name;

    #pragma unroll
    for (int i = 0; i < MAX_PATH_DEPTH; i++) {
        d_parent = BPF_CORE_READ(dentry, d_parent);
        if (dentry == d_parent)
            break;

        d_name = BPF_CORE_READ(dentry, d_name);

        len = (d_name.len + 1) & (MAX_DNAME_LEN - 1);
        off = buf_off - len;
        sz = 0;
        if (off <= buf_off) {
            len = len & ((MAX_PATH_LEN >> 1) - 1);
            sz = bpf_probe_read_str(&(pd->buf[off & ((MAX_PATH_LEN >> 1) - 1)]), len, (void *)d_name.name);
        } else {
            break;
        }

        if (sz > 1) {
            buf_off -= 1;
            bpf_probe_read(&(pd->buf[buf_off & (MAX_PATH_LEN - 1)]), 1, &slash);
            buf_off -= sz - 1;
        } else {
            break;
        }

        dentry = d_parent;
    }
    pd->truncated = dentry != d_parent;
    // prepend slash and null-terminate
    buf_off -= 1;
    bpf_probe_read(&(pd->buf[buf_off & (MAX_PATH_LEN - 1)]), 1, &slash);
    bpf_probe_read(&(pd->buf[(MAX_PATH_LEN >> 1) - 1]), 1, &zero);

    return buf_off;
}

SEC("lsm/path_chmod")
int BPF_PROG(my_chmod, struct path *path, umode_t mode) {
    struct path_data pd = {};
    read_path_data(path, &pd);
    bpf_printk("previous to blocking chmod on %s\n", pd.buf);

    if (__builtin_memcmp(pd.buf, "/tmp/prohibido.txt", 27) == 0) {
        bpf_printk("Blocking chmod on %s\n", pd.buf);
        return -EPERM;
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";