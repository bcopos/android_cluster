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
    * ~~kernel_cgroup.c~~
        * patch adds code at the end of file, however v30 is very different thant v29, so this MAY NOT WORK
    * ~~kernel_exit.c~~
        * minor differences, seems OK
    * ~~kernel_fork.c~~
        * some "includes" missing
    * kernel_pid.c
    * kernel_ptrace.c
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
    * ipc_Makefile
    * ~~ipc_namespace.c~~
    * ~~ipc_util.h~~
* Makefile
