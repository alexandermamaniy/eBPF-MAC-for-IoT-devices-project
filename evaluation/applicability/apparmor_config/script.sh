#!/bin/bash

# This script evaluates the performance of AppArmor by measuring syscall latencies.
# It runs a series of syscall latency tests using lmbench(20 times).

for i in $(seq 1 20)
do
    echo "Iteration number $i"
    /usr/lib/lmbench/bin/x86_64-linux-gnu/lat_syscall stat
    /usr/lib/lmbench/bin/x86_64-linux-gnu/lat_syscall open
    /usr/lib/lmbench/bin/x86_64-linux-gnu/lat_syscall read
    /usr/lib/lmbench/bin/x86_64-linux-gnu/lat_syscall write
    /usr/lib/lmbench/bin/x86_64-linux-gnu/lat_fs -N 10
done