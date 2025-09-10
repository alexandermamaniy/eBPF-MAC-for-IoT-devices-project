#!/bin/bash

# This script creates and mounts various file systems in Linux.


rm /tmp/*.img 2>/dev/null


# cramfs
mkdir -p /tmp/cramfs_root
echo "Hi from restricted CramFS" > /tmp/cramfs_root/restricted.txt
echo "Hi from unrestricted CramFS" > /tmp/cramfs_root/unrestricted.txt
mkfs.cramfs /tmp/cramfs_root /tmp/cramfs.img
mkdir -p /mnt/cramfs
mount -o loop /tmp/cramfs.img /mnt/cramfs


# romfs
mkdir -p /tmp/romfs_root
mkdir -p  /mnt/romfs
echo "Hi from restricted romfs" > /tmp/romfs_root/restricted.txt
echo "Hi from unrestricted romfs" > /tmp/romfs_root/unrestricted.txt
genromfs -d /tmp/romfs_root -f /tmp/romfs.img
mount -o loop -t romfs /tmp/romfs.img /mnt/romfs

# jffs2
modprobe mtdram total_size=4096 erase_size=128
modprobe mtdblock
mkdir -p  /tmp/jffs2_root
echo "Hi from restricted jffs2" > /tmp/jffs2_root/restricted.txt
echo "Hi from unrestricted jffs2" > /tmp/jffs2_root/unrestricted.txt
mkfs.jffs2 -d /tmp/jffs2_root -o /tmp/jffs2.img
dd if=/tmp/jffs2.img of=/dev/mtdblock0
mkdir -p /mnt/jffs2
mount -t jffs2 /dev/mtdblock0 /mnt/jffs2

# squashfs
mkdir -p /tmp/squashfs_root
echo "Hi from restricted squashfs" > /tmp/squashfs_root/restricted.txt
echo "Hi from unrestricted squashfs" > /tmp/squashfs_root/unrestricted.txt
mksquashfs /tmp/squashfs_root /tmp/squashfs.img
mkdir -p /mnt/squashfs
mount -o loop -t squashfs /tmp/squashfs.img /mnt/squashfs

# tmpfs
mkdir -p /mnt/tmpfs
mount -t tmpfs -o size=100M tmpfs /mnt/tmpfs
echo "Hi from restricted tmpfs" > /mnt/tmpfs/restricted.txt
echo "Hi from unrestricted tmpfs" > /mnt/tmpfs/unrestricted.txt


# Clean up

#umount /mnt/cramfs
#umount /mnt/romfs
#umount /mnt/jffs2
#umount /mnt/squashfs
#umount /mnt/tmpfs

#rmmod mtdblock
#rmmod mtdram