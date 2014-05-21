linux 2.6.29 kerrighed
======================

NETWORK IN QEMU:

1. ifconfig eth0 up
2. udhcpc
3. check ifconfig or try ping-ing


INSTRUCTIONS TO QUICKLY BOOT IMAGE:

1. install qemu
2. edit path in run.sh if bash shell is not located at /bin/bash
3. ./run.sh


INSTRUCTIONS FOR ROOTFS:

1. Download Buildroot src
2. make help
3. choose an option from two and make
4. rootfs img will be in output/images

Hints:
- run menuconfig to add utilities and libraries (openssh, openssl, etc)
- if needed, use glibc toolchain (toolchain options)
- populate dev (tty, tty1, null, urandom)
- edit etc/network/interfaces to have internet access 
- mount rootfs image and install kerrighed there (prefix=/path/to/rootfs/mount)
- copy /lib/lsb/init-functions from ubuntu vm or somewhere... kerrighed-host uses it

INSTRUCTIONS FOR QEMU:

- qemu-system-x86_64 -kernel [path]/[to]/bzImage -initrd [path]/[to]/rootfs.img -append "root=/dev/ram"
	OR
- qemu-system-x86_64 -kernel [path]/[to]/bzImage -initrd [path]/[to]/rootfs.img -nographic -append "root=/dev/ram console=ttyS0,115200" -vga vmware

Links:
1. http://www.tldp.org/HOWTO/Bootdisk-HOWTO/buildroot.html

INSTRUCTION FOR BUILDING KERRIGHED LIBS AND APPS:
1. inside kerrighed dir: ./configure -disable-kernel
2. make distclean
3. ./autogen.sh
4. ./configure --disable-kernel --prefix=/path/to/
5. make install

INSTRUCTIONS FOR BUILDING KERNEL:

1. cp -R linux-2.6.29 kerrighed/patches/.
2. inside kerrighed dir: ./configure i386_defconfig or x86_64_defconfig(?)
3. make kernel(use gcc-4.4)
4. bzImage file will be in kerrighed/kernel/arch/x86/boot/

NOTES:
- use gcc-4.4
- kerrighed will download linux-2.6.29.tar.bz -- this is OK
- however, make sure that during the configuration process, it does NOT unzip the linux source it just downloaded and instead uses the one already in the patches directory
- the linux-2.6.29 in the kerrighed/patches directory is a symlink to the linux-2.6.29 in the root directory of the repo


Failed patches
* include
    * ~~include_linux_ipc_namespace_.h~~
        * although 3 statments at the top of the patch are missing from 2.6.29, it seems like the hunk is to remove a blank line... seems OK!
    * ~~include_linux_init_task.h~~
    * ~~include_linux_magic.h~~
        * line missing "#define STACK_END_MAGIC 0x57AC6E9D" but may not be important, seems OK
    * ~~include_linux_sched.h~~
        * line missing "unsigned in_execve:1" but irrelevant, seems OK
    * ~~include_linux_tracehook.h~~
* net
    * ~~net_tipc_bcast.c~~
    * ~~net_tipc_bcast.h~~
        * for bcast.c/h seems like the patch tried to remove files but minor differences got in the way... might be OK
    * ~~net_tipc_dbg.c~~
        * patch tries to remove files but minor differences (line 261, printf) it couldn't... seems OK 
    * ~~net_tipc_node.c~~
        * same story as above... seems OK
* mm
    * ~~mm_vmscan.c~~
        * minor differences... seems OK
* kernel
    * ~~kernel_auditsc.c~~
        * line missing "include <linux/fs_struct.h>", irrelevant to patch... seems OK
    * ~~kernel_cgroup.c~~
        * patch adds code at the end of file, however v30 is very different thant v29, so this MAY NOT WORK
    * ~~kernel_exit.c~~
        * minor differences, seems OK
    * ~~kernel_fork.c~~
        * some "includes" missing
    * kernel_pid.c
    * ~~kernel_ptrace.c~~
        * last function to be patched (exit_ptrace) doesn't exist... REVISIT!
    * ~~kernel_sched.c~~
        * function to be patched (__schedule) doesn't exist but the code is in schedule() instead, applied patches there
* arch
    * arch_x86_configs_i386_defconfig
    * arch_x86_configs_x86_64_defconfig
    * ~~arch_x86_include_asm_pgtable_types.h~~
        * code for patch was in pgtable.h instead, applied patches there, seems OK
    * ~~arch_x86_include_asm_thread_info.h~~
        * define was missing, seems OK
    * ~~arch_x86_include_asm_uaccess.h~~
        * minor differences (errret v30 vs. -EFAULT v29 and others), seems OK 
    * ~~arch_x86_kernel_cpu_proc.c~~
        * different function call for cpu_mask, seems OK
    * ~~arch_x86_kernel_process_32.c~~
        * line after patch (312-ish) is different, REVISIT THIS
    * ~~arch_x86_kernel_process.c~~
        * code for patch was moved from process_32/64, so I applied patch directly there, seems OK
* fs
    * ~~fs_binfmt_elf_fdpic.c~~
        * task_pid_vnr(p->real_parent) (30) vs. task_pid_vnr(p->parent) (29)...
    * ~~fs_eventpoll.c~~
        * OK
    * ~~fs_exec.c~~
        * import missing (hunk1), 2 lines after comment missing in 29 (hunk2), seems OK
    * ~~fs_inode.c~~
        * lines following patch were different, seems OK
    * ~~fs_nfs_inode.c~~
        * a conditional statement is missing from 29 but is irrelevant, seems OK
    * ~~fs_open.c~~
        * import missing, seems OK
    * ~~fs_proc_base.c~~
        * import missing, seems OK
    * ~~fs_proc_uptime.c~~
        * uptime_proc_show (30) is the same-ish as uptime_proc_read (29) but function name and params are diff. Patch only changes the function type (from static to not), seems OK
    * ~~fs_stat.c~~
        * function is replaced in 2.6.30, but contents are similar, modified 29 to be similar to 30 and applied patch, seems OK
* ipc
    * ~~ipc_Makefile~~
    * ~~ipc_namespace.c~~
    * ~~ipc_util.h~~
* Makefile
	* added "-krg" to EXTRAVERSION variable of Makefile (line 4 or something)
