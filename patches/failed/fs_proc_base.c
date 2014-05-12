--- a/fs/proc/base.c
+++ b/fs/proc/base.c
@@ -81,6 +81,16 @@
 #include <linux/elf.h>
 #include <linux/pid_namespace.h>
 #include <linux/fs_struct.h>
+#ifdef CONFIG_KRG_KDDM
+#include <kerrighed/krgnodemask.h>
+#include <kddm/kddm.h>
+#endif
+#if defined(CONFIG_KRG_PROCFS) && defined(CONFIG_KRG_PROC)
+#include <kerrighed/pid.h>
+#endif
+#ifdef CONFIG_KRG_FAF
+#include <kerrighed/faf.h>
+#endif
 #include "internal.h"
 
 /* NOTE:
@@ -253,7 +263,10 @@ out:
 	return NULL;
 }
 
-static int proc_pid_cmdline(struct task_struct *task, char * buffer)
+#if !defined(CONFIG_KRG_PROCFS) || !defined(CONFIG_KRG_PROC)
+static
+#endif
+int proc_pid_cmdline(struct task_struct *task, char * buffer)
 {
 	int res = 0;
 	unsigned int len;
@@ -290,7 +303,11 @@ out:
 	return res;
 }
 
-static int proc_pid_auxv(struct task_struct *task, char *buffer)
+
+#if !defined(CONFIG_KRG_PROCFS) || !defined(CONFIG_KRG_PROC)
+static
+#endif
+int proc_pid_auxv(struct task_struct *task, char *buffer)
 {
 	int res = 0;
 	struct mm_struct *mm = get_task_mm(task);
@@ -314,7 +331,10 @@ static int proc_pid_auxv(struct task_struct *task, char *buffer)
  * Provides a wchan file via kallsyms in a proper one-value-per-file format.
  * Returns the resolved symbol.  If that fails, simply return the address.
  */
-static int proc_pid_wchan(struct task_struct *task, char *buffer)
+#if !defined(CONFIG_KRG_PROCFS) || !defined(CONFIG_KRG_PROC)
+static
+#endif
+int proc_pid_wchan(struct task_struct *task, char *buffer)
 {
 	unsigned long wchan;
 	char symname[KSYM_NAME_LEN];
@@ -335,7 +355,10 @@ static int proc_pid_wchan(struct task_struct *task, char *buffer)
 
 #define MAX_STACK_TRACE_DEPTH	64
 
-static int proc_pid_stack(struct seq_file *m, struct pid_namespace *ns,
+#if !defined(CONFIG_KRG_PROCFS) || !defined(CONFIG_KRG_PROC)
+static
+#endif
+int proc_pid_stack(struct seq_file *m, struct pid_namespace *ns,
 			  struct pid *pid, struct task_struct *task)
 {
 	struct stack_trace trace;
@@ -366,7 +389,10 @@ static int proc_pid_stack(struct seq_file *m, struct pid_namespace *ns,
 /*
  * Provides /proc/PID/schedstat
  */
-static int proc_pid_schedstat(struct task_struct *task, char *buffer)
+#if !defined(CONFIG_KRG_PROCFS) || !defined(CONFIG_KRG_PROC)
+static
+#endif
+int proc_pid_schedstat(struct task_struct *task, char *buffer)
 {
 	return sprintf(buffer, "%llu %llu %lu\n",
 			(unsigned long long)task->se.sum_exec_runtime,
@@ -443,7 +469,10 @@ static const struct file_operations proc_lstats_operations = {
 
 /* The badness from the OOM killer */
 unsigned long badness(struct task_struct *p, unsigned long uptime);
-static int proc_oom_score(struct task_struct *task, char *buffer)
+#if !defined(CONFIG_KRG_PROCFS) || !defined(CONFIG_KRG_PROC)
+static
+#endif
+int proc_oom_score(struct task_struct *task, char *buffer)
 {
 	unsigned long points;
 	struct timespec uptime;
@@ -480,7 +509,10 @@ static const struct limit_names lnames[RLIM_NLIMITS] = {
 };
 
 /* Display limits for a process */
-static int proc_pid_limits(struct task_struct *task, char *buffer)
+#if !defined(CONFIG_KRG_PROCFS) || !defined(CONFIG_KRG_PROC)
+static
+#endif
+int proc_pid_limits(struct task_struct *task, char *buffer)
 {
 	unsigned int i;
 	int count = 0;
@@ -525,7 +557,10 @@ static int proc_pid_limits(struct task_struct *task, char *buffer)
 }
 
 #ifdef CONFIG_HAVE_ARCH_TRACEHOOK
-static int proc_pid_syscall(struct task_struct *task, char *buffer)
+#if !defined(CONFIG_KRG_PROCFS) || !defined(CONFIG_KRG_PROC)
+static
+#endif
+int proc_pid_syscall(struct task_struct *task, char *buffer)
 {
 	long nr;
 	unsigned long args[6], sp, pc;
@@ -544,6 +579,84 @@ static int proc_pid_syscall(struct task_struct *task, char *buffer)
 }
 #endif /* CONFIG_HAVE_ARCH_TRACEHOOK */
 
+#ifdef CONFIG_KRG_KDDM
+
+static int proc_kddm_print_wq(char *buffer, wait_queue_head_t *q)
+{
+	wait_queue_t *curr;
+	int len = 0;
+
+	list_for_each_entry(curr, &q->task_list, task_list) {
+		struct task_struct *tsk = curr->private;
+
+		len += sprintf (buffer +len, "%s (%d) ", tsk->comm, tsk->pid);
+	}
+	return len;
+}
+
+static int proc_tid_kddm(struct task_struct *task, char *buffer)
+{
+	struct kddm_info_struct info;
+	struct kddm_set *set;
+	struct kddm_obj *obj_entry;
+	int len = 0;
+
+	if (!task->kddm_info)
+		goto done;
+	info = *task->kddm_info;
+
+	len += sprintf (buffer + len, "Get Object:          %ld\n",
+			info.get_object_counter);
+
+	len += sprintf (buffer + len, "Grab Object:         %ld\n",
+			info.grab_object_counter);
+
+	len += sprintf (buffer + len, "Remove Object:       %ld\n",
+			info.remove_object_counter);
+
+	len += sprintf (buffer + len, "Flush Object:        %ld\n",
+			info.flush_object_counter);
+
+
+	obj_entry = get_kddm_obj_entry(info.ns_id, info.set_id, info.obj_id,
+				       &set);
+	if (!set)
+		goto done;
+	if (!obj_entry || obj_entry != info.wait_obj)
+		goto unlock;
+
+	len += sprintf (buffer + len, "Process wait on object "
+			"(%d;%ld;%ld) %p with state %s\n",
+			info.ns_id, info.set_id,
+			info.obj_id, obj_entry,
+			STATE_NAME (OBJ_STATE(obj_entry)));
+
+	len += sprintf (buffer + len, "  * Probe owner:   %d\n",
+			get_prob_owner(obj_entry));
+	len += sprintf (buffer + len, "  * Frozen count:  %d\n",
+			atomic_read(&obj_entry->frozen_count));
+	len += sprintf (buffer + len, "  * Sleeper count: %d\n",
+			atomic_read(&obj_entry->sleeper_count));
+	len += sprintf (buffer + len, "  * Object:        %p\n",
+			obj_entry->object);
+	len += sprintf (buffer + len, "  * Copy set: ");
+	len += krgnodemask_scnprintf(buffer + len, PAGE_SIZE - len,
+				     obj_entry->master_obj.copyset);
+	len += sprintf (buffer + len, "\n  * Remove set: ");
+	len += krgnodemask_scnprintf(buffer + len, PAGE_SIZE - len,
+				     obj_entry->master_obj.copyset);
+	len += sprintf (buffer + len, "\n  * Waiting processes: ");
+	len += proc_kddm_print_wq (buffer + len, &obj_entry->waiting_tsk);
+	len += sprintf (buffer + len, "\n");
+unlock:
+	put_kddm_obj_entry(set, obj_entry, info.obj_id);
+done:
+
+	return len;
+}
+
+#endif /* CONFIG_KRG_KDDM */
+
 /************************************************************************/
 /*                       Here the fs part begins                        */
 /************************************************************************/
@@ -565,7 +678,10 @@ static int proc_fd_access_allowed(struct inode *inode)
 	return allowed;
 }
 
-static int proc_setattr(struct dentry *dentry, struct iattr *attr)
+#if !defined(CONFIG_KRG_PROCFS) || !defined(CONFIG_KRG_PROC)
+static
+#endif
+int proc_setattr(struct dentry *dentry, struct iattr *attr)
 {
 	int error;
 	struct inode *inode = dentry->d_inode;
@@ -579,7 +695,10 @@ static int proc_setattr(struct dentry *dentry, struct iattr *attr)
 	return error;
 }
 
-static const struct inode_operations proc_def_inode_operations = {
+#if !defined(CONFIG_KRG_PROCFS) || !defined(CONFIG_KRG_PROC)
+static
+#endif
+const struct inode_operations proc_def_inode_operations = {
 	.setattr	= proc_setattr,
 };
 
@@ -1344,7 +1463,10 @@ out:
 	return ERR_PTR(error);
 }
 
-static int do_proc_readlink(struct path *path, char __user *buffer, int buflen)
+#if !defined(CONFIG_KRG_PROCFS) || !defined(CONFIG_KRG_PROC)
+static
+#endif
+int do_proc_readlink(struct path *path, char __user *buffer, int buflen)
 {
 	char *tmp = (char*)__get_free_page(GFP_TEMPORARY);
 	char *pathname;
@@ -1353,6 +1475,11 @@ static int do_proc_readlink(struct path *path, char __user *buffer, int buflen)
 	if (!tmp)
 		return -ENOMEM;
 
+#ifdef CONFIG_KRG_FAF
+	if (!path->dentry && path->mnt)
+		pathname = krg_faf_d_path((struct file *)path->mnt, tmp, PAGE_SIZE, NULL);
+	else
+#endif
 	pathname = d_path(path, tmp, PAGE_SIZE);
 	len = PTR_ERR(pathname);
 	if (IS_ERR(pathname))
@@ -1383,6 +1510,12 @@ static int proc_pid_readlink(struct dentry * dentry, char __user * buffer, int b
 		goto out;
 
 	error = do_proc_readlink(&path, buffer, buflen);
+#ifdef CONFIG_KRG_FAF
+	if (!path.dentry && path.mnt) {
+		fput((struct file *)path.mnt);
+		goto out;
+	}
+#endif
 	path_put(&path);
 out:
 	return error;
@@ -1501,7 +1634,11 @@ static int pid_revalidate(struct dentry *dentry, struct nameidata *nd)
 	struct task_struct *task = get_proc_task(inode);
 	const struct cred *cred;
 
+#if defined(CONFIG_KRG_PROCFS) && defined(CONFIG_KRG_EPM)
+	if (task && task->exit_state != EXIT_MIGRATION) {
+#else
 	if (task) {
+#endif
 		if ((inode->i_mode == (S_IFDIR|S_IRUGO|S_IXUGO)) ||
 		    task_dumpable(task)) {
 			rcu_read_lock();
@@ -1642,13 +1779,28 @@ static int proc_fd_info(struct inode *inode, struct path *path, char *info)
 			if (path) {
 				*path = file->f_path;
 				path_get(&file->f_path);
+#ifdef CONFIG_KRG_FAF
+				if (file->f_flags & O_FAF_CLT) {
+					get_file(file);
+					path->mnt = (struct vfsmount *)file;
+					/* path->dentry = NULL; */
+				}
+#endif
 			}
 			if (info)
+#ifdef CONFIG_KRG_FAF
+				snprintf(info, PROC_FDINFO_MAX,
+					 "pos:\t%lli\n"
+					 "flags:\t0%o\n",
+					 (long long) file->f_pos,
+					 (unsigned int)(file->f_flags & ~(unsigned long)O_KRG_FLAGS));
+#else
 				snprintf(info, PROC_FDINFO_MAX,
 					 "pos:\t%lli\n"
 					 "flags:\t0%o\n",
 					 (long long) file->f_pos,
 					 file->f_flags);
+#endif
 			spin_unlock(&files->file_lock);
 			put_files_struct(files);
 			return 0;
@@ -2450,13 +2602,19 @@ static int proc_tid_io_accounting(struct task_struct *task, char *buffer)
 	return do_io_accounting(task, buffer, 0);
 }
 
-static int proc_tgid_io_accounting(struct task_struct *task, char *buffer)
+#if !defined(CONFIG_KRG_PROCFS) || !defined(CONFIG_KRG_PROC)
+static
+#endif
+int proc_tgid_io_accounting(struct task_struct *task, char *buffer)
 {
 	return do_io_accounting(task, buffer, 1);
 }
 #endif /* CONFIG_TASK_IO_ACCOUNTING */
 
-static int proc_pid_personality(struct seq_file *m, struct pid_namespace *ns,
+#if !defined(CONFIG_KRG_PROCFS) || !defined(CONFIG_KRG_PROC)
+static
+#endif
+int proc_pid_personality(struct seq_file *m, struct pid_namespace *ns,
 				struct pid *pid, struct task_struct *task)
 {
 	seq_printf(m, "%08x\n", task->personality);
@@ -2711,9 +2869,36 @@ struct dentry *proc_pid_lookup(struct inode *dir, struct dentry * dentry, struct
 		get_task_struct(task);
 	rcu_read_unlock();
 	if (!task)
-		goto out;
+#if defined(CONFIG_KRG_PROCFS) && defined(CONFIG_KRG_PROC)
+	{
+		if (current->nsproxy->krg_ns
+		    && is_krg_pid_ns_root(ns) && (tgid & GLOBAL_PID_MASK))
+			result = krg_proc_pid_lookup(dir, dentry, tgid);
+#endif
+                goto out;
+#if defined(CONFIG_KRG_PROCFS) && defined(CONFIG_KRG_PROC)
+	}
+#endif
 
 	result = proc_pid_instantiate(dir, dentry, task, NULL);
+#if defined(CONFIG_KRG_PROCFS) && defined(CONFIG_KRG_EPM)
+	if (current->nsproxy->krg_ns
+	    && IS_ERR(result) && task->exit_state == EXIT_MIGRATION) {
+		/*
+		 * proc_pid_instantiate() may have instantiated dentry, but we
+		 * don't know, so restart with a fresh one.
+		 */
+		result = ERR_PTR(-ENOMEM);
+		dentry = d_alloc(dentry->d_parent, &dentry->d_name);
+		if (dentry) {
+			result = krg_proc_pid_lookup(dir, dentry, tgid);
+			if (!result)
+				result = dentry;
+			else
+				dput(dentry);
+		}
+	}
+#endif
 	put_task_struct(task);
 out:
 	return result;
@@ -2723,10 +2908,14 @@ out:
  * Find the first task with tgid >= tgid
  *
  */
+#if !defined(CONFIG_KRG_PROCFS) || !defined(CONFIG_KRG_PROC)
 struct tgid_iter {
 	unsigned int tgid;
 	struct task_struct *task;
 };
+#else
+/* moved into include/linux/procfs_internal.h */
+#endif
 static struct tgid_iter next_tgid(struct pid_namespace *ns, struct tgid_iter iter)
 {
 	struct pid *pid;
@@ -2764,7 +2953,10 @@ retry:
 
 #define TGID_OFFSET (FIRST_PROCESS_ENTRY + ARRAY_SIZE(proc_base_stuff))
 
-static int proc_pid_fill_cache(struct file *filp, void *dirent, filldir_t filldir,
+#if !defined(CONFIG_KRG_PROCFS) || !defined(CONFIG_KRG_PROC)
+static
+#endif
+int proc_pid_fill_cache(struct file *filp, void *dirent, filldir_t filldir,
 	struct tgid_iter iter)
 {
 	char name[PROC_NUMBUF];
@@ -2793,6 +2985,13 @@ int proc_pid_readdir(struct file * filp, void * dirent, filldir_t filldir)
 	ns = filp->f_dentry->d_sb->s_fs_info;
 	iter.task = NULL;
 	iter.tgid = filp->f_pos - TGID_OFFSET;
+#if defined(CONFIG_KRG_PROCFS) && defined(CONFIG_KRG_PROC)
+	if (current->nsproxy->krg_ns && is_krg_pid_ns_root(ns)) {
+		/* All filling is done by krg_proc_pid_readdir */
+		if (krg_proc_pid_readdir(filp, dirent, filldir, TGID_OFFSET))
+			goto out;
+	} else
+#endif
 	for (iter = next_tgid(ns, iter);
 	     iter.task;
 	     iter.tgid += 1, iter = next_tgid(ns, iter)) {
@@ -2802,7 +3001,11 @@ int proc_pid_readdir(struct file * filp, void * dirent, filldir_t filldir)
 			goto out;
 		}
 	}
+#if defined(CONFIG_KRG_PROCFS) && defined(CONFIG_KRG_PROC)
+	filp->f_pos = KERRIGHED_PID_MAX_LIMIT + TGID_OFFSET;
+#else
 	filp->f_pos = PID_MAX_LIMIT + TGID_OFFSET;
+#endif
 out:
 	put_task_struct(reaper);
 out_no_task:
@@ -2829,6 +3032,9 @@ static const struct pid_entry tid_base_stuff[] = {
 	INF("cmdline",   S_IRUGO, proc_pid_cmdline),
 	ONE("stat",      S_IRUGO, proc_tid_stat),
 	ONE("statm",     S_IRUGO, proc_pid_statm),
+#ifdef CONFIG_KRG_KDDM
+	INF("kddm",      S_IRUGO, proc_tid_kddm),
+#endif
 	REG("maps",      S_IRUGO, proc_maps_operations),
 #ifdef CONFIG_NUMA
 	REG("numa_maps", S_IRUGO, proc_numa_maps_operations),
diff --git a/fs/proc/inode.c b/fs/proc/inode.c
index d78ade3..2e879bd 100644
