linux 2.6.29 kerrighed
======================


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
    * mm_vmscan.c
* kernel
    * ~~kernel_auditsc.c~~
        * line missing "include <linux/fs_struct.h>", irrelevant to patch... seems OK
    * kernel_cgroup.c
    * kernel_exit.c
    * ~~kernel_fork.c~~
        * some "includes" missing
    * kernel_pid.c
    * kernel_ptrace.c
    * kernel_sched.c
* arch
    * arch_x86_configs_i386_defconfig
    * arch_x86_configs_x86_64_defconfig
    * arch_x86_include_asm_pgtable_types.h
    * arch_x86_include_asm_thread_info.h
    * arch_x86_include_asm_uaccess.h
    * arch_x86_kernel_cpu_proc.c
    * arch_x86_kernel_process_32.c
    * arch_x86_kernel_process.c
* fs
    * fs_binfmt_elf_fdpic.c
    * fs_eventpoll.c
    * fs_exec.c
    * fs_inode.c
    * fs_nfs_inode.c
    * fs_open.c
    * fs_proc_base.c
    * fs_proc_uptime.c
    * fs_stat.c
* ipc
    * ipc_Makefile
    * ~~ipc_namespace.c~~
    * ~~ipc_util.h~~
* Makefile
