#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1
#define MAX_PATH_LEN 256

// Define the paths that are restricted
const char restricted_paths[][MAX_PATH_LEN] = {
    "/mnt/cramfs/restricted.txt",
    "/mnt/jffs2/restricted.txt",
    "/mnt/romfs/restricted.txt",
    "/mnt/squashfs/restricted.txt",
    "/mnt/tmpfs/restricted.txt"
};
// Define the paths that are not restricted
const char unrestricted_paths[][MAX_PATH_LEN] = {
    "/mnt/cramfs/unrestricted.txt",
    "/mnt/jffs2/unrestricted.txt",
    "/mnt/romfs/unrestricted.txt",
    "/mnt/squashfs/unrestricted.txt",
    "/mnt/tmpfs/unrestricted.txt"
};

#define NUM_PATHS 5

// LSM hook that denies file open operations on restricted paths
// If the path is in unrestricted paths, allow the operation
// If the path is in restricted paths, deny the operation

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
        if (__builtin_memcmp(buf, unrestricted_paths[i], __builtin_strlen(unrestricted_paths[i])) == 0) {
            return 0;
        }
    }

#pragma unroll
    for (int i = 0; i < NUM_PATHS; i++) {
        if (__builtin_memcmp(buf, restricted_paths[i], __builtin_strlen(restricted_paths[i])) == 0) {
            bpf_printk("lsm: denying open of %s", buf);
            return -EPERM;
        }
    }
    return 0;
}