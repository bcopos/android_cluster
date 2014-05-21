#! /bin/bash

qemu-system-x86_64 -kernel images/5.19/bzImage.64 -initrd images/rootfs/rootfs_glibc.ext3 -append "ramdisk_size=128000 root=/dev/ram session_id=1 node_id=1"
#qemu-system-x86_64 -kernel images/5.19/bzImage -initrd /Applications/Android/system-images/android-19/x86/system.img -append "session_id=1 node_id=1"
