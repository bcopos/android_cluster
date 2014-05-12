--- a/kernel/exit.c
+++ b/kernel/exit.c
@@ -49,6 +49,24 @@
 #include <linux/fs_struct.h>
 #include <linux/init_task.h>
 #include <trace/sched.h>
+#ifdef CONFIG_KRG_KDDM
+#include <kddm/kddm_info.h>
+#endif
+#ifdef CONFIG_KRG_HOTPLUG
+#include <kerrighed/namespace.h>
+#endif
+#ifdef CONFIG_KRG_PROC
+#include <kerrighed/task.h>
+#include <kerrighed/krginit.h>
+#include <kerrighed/krg_exit.h>
+#endif
+#ifdef CONFIG_KRG_EPM
+#include <kerrighed/signal.h>
+#include <kerrighed/children.h>
+#endif
+#ifdef CONFIG_KRG_SCHED
+#include <kerrighed/scheduler/info.h>
+#endif
 
 #include <asm/uaccess.h>
 #include <asm/unistd.h>
@@ -60,7 +78,10 @@ DEFINE_TRACE(sched_process_free);
 DEFINE_TRACE(sched_process_exit);
 DEFINE_TRACE(sched_process_wait);
 
-static void exit_mm(struct task_struct * tsk);
+#ifndef CONFIG_KRG_MM
+static
+#endif
+void exit_mm(struct task_struct * tsk);
 
 static void __unhash_process(struct task_struct *p)
 {
@@ -92,6 +113,13 @@ static void __exit_signal(struct task_struct *tsk)
 	spin_lock(&sighand->siglock);
 
 	posix_cpu_timers_exit(tsk);
+#ifdef CONFIG_KRG_EPM
+	if (tsk->exit_state == EXIT_MIGRATION) {
+		BUG_ON(atomic_read(&sig->count) > 1);
+		posix_cpu_timers_exit_group(tsk);
+		sig->curr_target = NULL;
+	} else
+#endif
 	if (atomic_dec_and_test(&sig->count))
 		posix_cpu_timers_exit_group(tsk);
 	else {
@@ -140,16 +168,30 @@ static void __exit_signal(struct task_struct *tsk)
 	tsk->sighand = NULL;
 	spin_unlock(&sighand->siglock);
 
+#ifdef CONFIG_KRG_EPM
+	if (tsk->exit_state == EXIT_MIGRATION)
+		krg_sighand_unpin(sighand);
+	else
+#endif
 	__cleanup_sighand(sighand);
 	clear_tsk_thread_flag(tsk,TIF_SIGPENDING);
 	if (sig) {
 		flush_sigqueue(&sig->shared_pending);
+#ifdef CONFIG_KRG_EPM
+		if (tsk->exit_state != EXIT_MIGRATION)
+#endif
 		taskstats_tgid_free(sig);
 		/*
 		 * Make sure ->signal can't go away under rq->lock,
 		 * see account_group_exec_runtime().
 		 */
 		task_rq_unlock_wait(tsk);
+#ifdef CONFIG_KRG_EPM
+		if (tsk->exit_state == EXIT_MIGRATION) {
+			krg_signal_unpin(sig);
+			return;
+		}
+#endif
 		__cleanup_signal(sig);
 	}
 }
@@ -167,7 +209,36 @@ void release_task(struct task_struct * p)
 {
 	struct task_struct *leader;
 	int zap_leader;
+#ifdef CONFIG_KRG_EPM
+	struct signal_struct *locked_sig;
+	unsigned long locked_sighand_id;
+	int delay_notify_parent = 0;
+
+	/*
+	 * Because we may have to release the group leader at the same time and
+	 * because with KRG_EPM this may need to do blocking operations in the
+	 * context of an unhashed task (current thread), we make sure that the
+	 * task that will do the job will remain a plain task during the whole
+	 * operation.
+	 */
+	if (krg_delay_release_task(p))
+		return;
+#endif /* CONFIG_KRG_EPM */
 repeat:
+#ifdef CONFIG_KRG_SCHED
+	krg_sched_info_free(p);
+#endif
+#ifdef CONFIG_KRG_PROC
+	krg_release_task(p);
+#endif /* CONFIG_KRG_PROC */
+#ifdef CONFIG_KRG_EPM
+	locked_sig = NULL;
+	locked_sighand_id = 0;
+	if (p->exit_state != EXIT_MIGRATION) {
+		locked_sig = krg_signal_exit(p->signal);
+		locked_sighand_id = krg_sighand_exit(p->sighand);
+	}
+#endif /* CONFIG_KRG_EPM */
 	tracehook_prepare_release_task(p);
 	/* don't need to get the RCU readlock here - the process is dead and
 	 * can't be modifying its own credentials */
@@ -187,6 +258,13 @@ repeat:
 	leader = p->group_leader;
 	if (leader != p && thread_group_empty(leader) && leader->exit_state == EXIT_ZOMBIE) {
 		BUG_ON(task_detached(leader));
+#ifdef CONFIG_KRG_EPM
+		if (leader->parent_children_obj) {
+			delay_notify_parent = 1;
+			leader->flags |= PF_DELAY_NOTIFY;
+			goto unlock;
+		}
+#endif
 		do_notify_parent(leader, leader->exit_signal);
 		/*
 		 * If we were the last child thread and the leader has
@@ -206,10 +284,27 @@ repeat:
 			leader->exit_state = EXIT_DEAD;
 	}
 
+#ifdef CONFIG_KRG_EPM
+unlock:
+#endif
 	write_unlock_irq(&tasklist_lock);
 	release_thread(p);
+#ifdef CONFIG_KRG_EPM
+	krg_children_cleanup(p);
+	if (locked_sighand_id)
+		krg_sighand_unlock(locked_sighand_id);
+	krg_signal_unlock(locked_sig);
+#endif
 	call_rcu(&p->rcu, delayed_put_task_struct);
 
+#ifdef CONFIG_KRG_EPM
+	if (delay_notify_parent) {
+		BUG_ON(p == current);
+		delay_notify_parent = 0;
+
+		zap_leader = krg_delayed_notify_parent(leader);
+	}
+#endif
 	p = leader;
 	if (unlikely(zap_leader))
 		goto repeat;
@@ -250,6 +345,9 @@ static int will_become_orphaned_pgrp(struct pid *pgrp, struct task_struct *ignor
 
 	do_each_pid_task(pgrp, PIDTYPE_PGID, p) {
 		if ((p == ignored_task) ||
+#ifdef CONFIG_KRG_EPM
+		    (p->real_parent == baby_sitter) ||
+#endif
 		    (p->exit_state && thread_group_empty(p)) ||
 		    is_global_init(p->real_parent))
 			continue;
@@ -308,6 +406,11 @@ kill_orphaned_pgrp(struct task_struct *tsk, struct task_struct *parent)
 		 * we are, and it was the only connection outside.
 		 */
 		ignored_task = NULL;
+#ifdef CONFIG_KRG_EPM
+	if (parent == baby_sitter)
+		/* TODO: check for orphaned pgrp with remote real_parent */
+		return;
+#endif
 
 	if (task_pgrp(parent) != pgrp &&
 	    task_session(parent) == task_session(tsk) &&
@@ -332,6 +435,17 @@ kill_orphaned_pgrp(struct task_struct *tsk, struct task_struct *parent)
  */
 static void reparent_to_kthreadd(void)
 {
+#ifdef CONFIG_KRG_EPM
+	struct children_kddm_object *parent_children_obj = NULL;
+	pid_t parent_tgid;
+
+	down_read(&kerrighed_init_sem);
+
+	if (rcu_dereference(current->parent_children_obj))
+		parent_children_obj = krg_parent_children_writelock(
+					current,
+					&parent_tgid);
+#endif /* CONFIG_KRG_EPM */
 	write_lock_irq(&tasklist_lock);
 
 	ptrace_unlink(current);
@@ -353,6 +467,15 @@ static void reparent_to_kthreadd(void)
 	atomic_inc(&init_cred.usage);
 	commit_creds(&init_cred);
 	write_unlock_irq(&tasklist_lock);
+#ifdef CONFIG_KRG_EPM
+	if (parent_children_obj) {
+		krg_set_child_ptraced(parent_children_obj, current, 0);
+		krg_remove_child(parent_children_obj, current);
+		krg_children_unlock(parent_children_obj);
+	}
+
+	up_read(&kerrighed_init_sem);
+#endif /* CONFIG_KRG_EPM */
 }
 
 void __set_special_pids(struct pid *pid)
@@ -641,7 +764,10 @@ assign_new_owner:
  * Turn us into a lazy TLB process if we
  * aren't already..
  */
-static void exit_mm(struct task_struct * tsk)
+#ifndef CONFIG_KRG_MM
+static
+#endif
+void exit_mm(struct task_struct * tsk)
 {
 	struct mm_struct *mm = tsk->mm;
 	struct core_state *core_state;
@@ -772,10 +898,17 @@ static void reparent_thread(struct task_struct *father, struct task_struct *p,
 static void forget_original_parent(struct task_struct *father)
 {
 	struct task_struct *p, *n, *reaper;
+#ifdef CONFIG_KRG_EPM
+	struct children_kddm_object *children_obj = NULL;
+#endif
 	LIST_HEAD(dead_children);
 
 	exit_ptrace(father);
 
+#ifdef CONFIG_KRG_EPM
+	if (rcu_dereference(father->children_obj))
+		children_obj = __krg_children_writelock(father);
+#endif
 	write_lock_irq(&tasklist_lock);
 	reaper = find_new_reaper(father);
 
@@ -785,9 +918,22 @@ static void forget_original_parent(struct task_struct *father)
 			BUG_ON(p->ptrace);
 			p->parent = p->real_parent;
 		}
+#ifdef CONFIG_KRG_EPM
+		else {
+			BUG_ON(!p->ptrace);
+			krg_ptrace_reparent_ptraced(father, p);
+		}
+#endif
 		reparent_thread(father, p, &dead_children);
 	}
 	write_unlock_irq(&tasklist_lock);
+#ifdef CONFIG_KRG_EPM
+	if (children_obj) {
+		/* Reparent remote children */
+		krg_forget_original_remote_parent(father, reaper);
+		krg_children_exit(father);
+	}
+#endif
 
 	BUG_ON(!list_empty(&father->children));
 
@@ -805,6 +951,12 @@ static void exit_notify(struct task_struct *tsk, int group_dead)
 {
 	int signal;
 	void *cookie;
+#ifdef CONFIG_KRG_PROC
+	void *krg_cookie;
+#endif
+#ifdef CONFIG_KRG_EPM
+	u32 real_parent_self_exec_id;
+#endif
 
 	/*
 	 * This does two things:
@@ -817,6 +969,9 @@ static void exit_notify(struct task_struct *tsk, int group_dead)
 	forget_original_parent(tsk);
 	exit_task_namespaces(tsk);
 
+#ifdef CONFIG_KRG_PROC
+	krg_cookie = krg_prepare_exit_notify(tsk);
+#endif /* CONFIG_KRG_PROC */
 	write_lock_irq(&tasklist_lock);
 	if (group_dead)
 		kill_orphaned_pgrp(tsk->group_leader, NULL);
@@ -835,10 +990,20 @@ static void exit_notify(struct task_struct *tsk, int group_dead)
 	 * we have changed execution domain as these two values started
 	 * the same after a fork.
 	 */
+#ifdef CONFIG_KRG_EPM
+	/* remote parent aware version of vanilla linux check (below) */
+	real_parent_self_exec_id = krg_get_real_parent_self_exec_id(tsk,
+								    krg_cookie);
+	if (tsk->exit_signal != SIGCHLD && !task_detached(tsk) &&
+	    (tsk->parent_exec_id != real_parent_self_exec_id ||
+	     tsk->self_exec_id != tsk->parent_exec_id))
+		tsk->exit_signal = SIGCHLD;
+#else
 	if (tsk->exit_signal != SIGCHLD && !task_detached(tsk) &&
 	    (tsk->parent_exec_id != tsk->real_parent->self_exec_id ||
 	     tsk->self_exec_id != tsk->parent_exec_id))
 		tsk->exit_signal = SIGCHLD;
+#endif
 
 	signal = tracehook_notify_death(tsk, &cookie, group_dead);
 	if (signal >= 0)
@@ -853,6 +1018,14 @@ static void exit_notify(struct task_struct *tsk, int group_dead)
 		wake_up_process(tsk->signal->group_exit_task);
 
 	write_unlock_irq(&tasklist_lock);
+#ifdef CONFIG_KRG_PROC
+	krg_finish_exit_notify(tsk, signal, krg_cookie);
+	/*
+	 * No kerrighed structure should be accessed after this point,
+	 * since the task may have already been released by its reaper.
+	 * The exception of course is the case in which the task self-reaps.
+	 */
+#endif /* CONFIG_KRG_PROC */
 
 	tracehook_report_death(tsk, signal, cookie, group_dead);
 
@@ -886,11 +1059,38 @@ static void check_stack_usage(void)
 static inline void check_stack_usage(void) {}
 #endif
 
+#ifdef CONFIG_KRG_EPM
+static void exit_migration(struct task_struct *tsk)
+{
+	/* Not a real exit... just a migration. */
+	exit_task_namespaces(tsk);
+
+	write_lock_irq(&tasklist_lock);
+	BUG_ON(!list_empty(&tsk->children));
+	BUG_ON(!list_empty(&tsk->ptraced));
+	BUG_ON(!list_empty(&tsk->ptrace_entry));
+
+	BUG_ON(tsk->parent != baby_sitter);
+	BUG_ON(tsk->real_parent != baby_sitter);
+
+	tsk->exit_state = EXIT_MIGRATION;
+	write_unlock_irq(&tasklist_lock);
+
+	release_task(tsk);
+}
+#endif /* CONFIG_KRG_EPM */
+
+#ifdef CONFIG_KRG_EPM
+static NORET_TYPE void __do_exit(long code, bool notify)
+#else
 NORET_TYPE void do_exit(long code)
+#endif
 {
 	struct task_struct *tsk = current;
 	int group_dead;
-
+#ifdef CONFIG_KRG_MM
+	struct mm_struct *mm = NULL;
+#endif
 	profile_task_exit(tsk);
 
 	WARN_ON(atomic_read(&tsk->fs_excl));
@@ -925,6 +1125,19 @@ NORET_TYPE void do_exit(long code)
 
 	exit_irq_thread();
 
+#ifdef CONFIG_KRG_HOTPLUG
+	if (tsk->nsproxy->krg_ns && tsk == tsk->nsproxy->krg_ns->root_task) {
+		krg_ns_root_exit(tsk);
+		printk(KERN_WARNING
+		       "kerrighed: Root task exiting! Leaking zombies.\n");
+		set_current_state(TASK_UNINTERRUPTIBLE);
+		schedule();
+	}
+#endif
+
+#ifdef CONFIG_KRG_PROC
+	down_read_non_owner(&kerrighed_init_sem);
+#endif
 	exit_signals(tsk);  /* sets PF_EXITING */
 	/*
 	 * tsk->flags are checked in the futex code to protect against
@@ -953,9 +1166,15 @@ NORET_TYPE void do_exit(long code)
 
 	tsk->exit_code = code;
 	taskstats_exit(tsk, group_dead);
-
+#ifdef CONFIG_KRG_MM
+	if (tsk->mm && tsk->mm->mm_id)
+		mm = tsk->mm;
+#endif
 	exit_mm(tsk);
-
+#ifdef CONFIG_KRG_MM
+	if (mm)
+		KRGFCT(kh_mm_release)(mm, notify);
+#endif
 	if (group_dead)
 		acct_process();
 	trace_sched_process_exit(tsk);
@@ -967,6 +1186,10 @@ NORET_TYPE void do_exit(long code)
 	exit_thread();
 	cgroup_exit(tsk, 1);
 
+#ifdef CONFIG_KRG_EPM
+	/* Do not kill the session when session leader only migrates */
+	if (notify)
+#endif
 	if (group_dead && tsk->signal->leader)
 		disassociate_ctty(1);
 
@@ -975,11 +1198,20 @@ NORET_TYPE void do_exit(long code)
 		module_put(tsk->binfmt->module);
 
 	proc_exit_connector(tsk);
+#ifdef CONFIG_KRG_EPM
+	if (!notify)
+		exit_migration(tsk);
+	else
+#endif
 	exit_notify(tsk, group_dead);
 #ifdef CONFIG_NUMA
 	mpol_put(tsk->mempolicy);
 	tsk->mempolicy = NULL;
 #endif
+#ifdef CONFIG_KRG_KDDM
+	if (tsk->kddm_info)
+		kmem_cache_free(kddm_info_cachep, tsk->kddm_info);
+#endif
 #ifdef CONFIG_FUTEX
 	/*
 	 * This must happen late, after the PID is not
@@ -1010,6 +1242,9 @@ NORET_TYPE void do_exit(long code)
 	preempt_disable();
 	/* causes final put_task_struct in finish_task_switch(). */
 	tsk->state = TASK_DEAD;
+#ifdef CONFIG_KRG_PROC
+	up_read_non_owner(&kerrighed_init_sem);
+#endif
 	schedule();
 	BUG();
 	/* Avoid "noreturn function does return".  */
@@ -1017,6 +1252,22 @@ NORET_TYPE void do_exit(long code)
 		cpu_relax();	/* For when BUG is null */
 }
 
+#ifdef CONFIG_KRG_EPM
+NORET_TYPE void do_exit(long code)
+{
+	__do_exit(code, true);
+	/* Avoid "noreturn function does return".  */
+	for (;;);
+}
+
+NORET_TYPE void do_exit_wo_notify(long code)
+{
+	__do_exit(code, false);
+	/* Avoid "noreturn function does return".  */
+	for (;;);
+}
+#endif /* CONFIG_KRG_EPM */
+
 EXPORT_SYMBOL_GPL(do_exit);
 
 NORET_TYPE void complete_and_exit(struct completion *comp, long code)
@@ -1144,7 +1395,10 @@ static int wait_noreap_copyout(struct task_struct *p, pid_t pid, uid_t uid,
  * the lock and this task is uninteresting.  If we return nonzero, we have
  * released the lock and the system call should return.
  */
-static int wait_task_zombie(struct task_struct *p, int options,
+#ifndef CONFIG_KRG_EPM
+static
+#endif
+int wait_task_zombie(struct task_struct *p, int options,
 			    struct siginfo __user *infop,
 			    int __user *stat_addr, struct rusage __user *ru)
 {
@@ -1162,6 +1416,11 @@ static int wait_task_zombie(struct task_struct *p, int options,
 
 		get_task_struct(p);
 		read_unlock(&tasklist_lock);
+#ifdef CONFIG_KRG_EPM
+		/* If caller is remote, current has no children object. */
+		if (current->children_obj)
+			krg_children_unlock(current->children_obj);
+#endif
 		if ((exit_code & 0x7f) == 0) {
 			why = CLD_EXITED;
 			status = exit_code >> 8;
@@ -1173,6 +1432,11 @@ static int wait_task_zombie(struct task_struct *p, int options,
 					   status, infop, ru);
 	}
 
+#ifdef CONFIG_KRG_EPM
+	/* Do not reap it yet, krg_delayed_notify_parent() has not finished. */
+	if (p->flags & PF_DELAY_NOTIFY)
+		return 0;
+#endif
 	/*
 	 * Try to move the task's state to DEAD
 	 * only one thread is allowed to do this:
@@ -1185,6 +1449,10 @@ static int wait_task_zombie(struct task_struct *p, int options,
 
 	traced = ptrace_reparented(p);
 
+#ifdef CONFIG_KRG_EPM
+	/* remote call iff p->parent == baby_sitter */
+	if (p->parent != baby_sitter)
+#endif
 	if (likely(!traced)) {
 		struct signal_struct *psig;
 		struct signal_struct *sig;
@@ -1250,6 +1518,10 @@ static int wait_task_zombie(struct task_struct *p, int options,
 	 * thread can reap it because we set its state to EXIT_DEAD.
 	 */
 	read_unlock(&tasklist_lock);
+#ifdef CONFIG_KRG_EPM
+	if (current->children_obj)
+		krg_children_unlock(current->children_obj);
+#endif
 
 	retval = ru ? getrusage(p, RUSAGE_BOTH, ru) : 0;
 	status = (p->signal->flags & SIGNAL_GROUP_EXIT)
@@ -1282,6 +1554,17 @@ static int wait_task_zombie(struct task_struct *p, int options,
 		retval = pid;
 
 	if (traced) {
+#ifdef CONFIG_KRG_EPM
+		struct children_kddm_object *parent_children_obj = NULL;
+		pid_t real_parent_tgid;
+		/* p may be set to NULL while we still need it */
+		struct task_struct *saved_p = p;
+
+		if (rcu_dereference(saved_p->parent_children_obj))
+			parent_children_obj =
+				krg_parent_children_writelock(saved_p,
+							      &real_parent_tgid);
+#endif
 		write_lock_irq(&tasklist_lock);
 		/* We dropped tasklist, ptracer could die and untrace */
 		ptrace_unlink(p);
@@ -1298,6 +1581,13 @@ static int wait_task_zombie(struct task_struct *p, int options,
 			}
 		}
 		write_unlock_irq(&tasklist_lock);
+#ifdef CONFIG_KRG_EPM
+		if (parent_children_obj) {
+			krg_set_child_ptraced(parent_children_obj, saved_p, 0);
+			krg_set_child_exit_signal(parent_children_obj, saved_p);
+			krg_children_unlock(parent_children_obj);
+		}
+#endif /* CONFIG_KRG_EPM */
 	}
 	if (p != NULL)
 		release_task(p);
@@ -1366,6 +1656,10 @@ unlock_sig:
 	pid = task_pid_vnr(p);
 	why = ptrace ? CLD_TRAPPED : CLD_STOPPED;
 	read_unlock(&tasklist_lock);
+#ifdef CONFIG_KRG_EPM
+	if (current->children_obj)
+		krg_children_unlock(current->children_obj);
+#endif
 
 	if (unlikely(options & WNOWAIT))
 		return wait_noreap_copyout(p, pid, uid,
@@ -1429,6 +1723,10 @@ static int wait_task_continued(struct task_struct *p, int options,
 	pid = task_pid_vnr(p);
 	get_task_struct(p);
 	read_unlock(&tasklist_lock);
+#ifdef CONFIG_KRG_EPM
+	if (current->children_obj)
+		krg_children_unlock(current->children_obj);
+#endif
 
 	if (!infop) {
 		retval = ru ? getrusage(p, RUSAGE_BOTH, ru) : 0;
@@ -1564,9 +1862,16 @@ static int ptrace_do_wait(struct task_struct *tsk, int *notask_error,
 	return 0;
 }
 
+#ifdef CONFIG_KRG_EPM
+static
+long do_wait(enum pid_type type, struct pid *pid, pid_t upid, int options,
+	     struct siginfo __user *infop, int __user *stat_addr,
+	     struct rusage __user *ru)
+#else
 static long do_wait(enum pid_type type, struct pid *pid, int options,
 		    struct siginfo __user *infop, int __user *stat_addr,
 		    struct rusage __user *ru)
+#endif
 {
 	DECLARE_WAITQUEUE(wait, current);
 	struct task_struct *tsk;
@@ -1574,6 +1879,9 @@ static long do_wait(enum pid_type type, struct pid *pid, int options,
 
 	trace_sched_process_wait(pid);
 
+#ifdef CONFIG_KRG_PROC
+	down_read(&kerrighed_init_sem);
+#endif
 	add_wait_queue(&current->signal->wait_chldexit,&wait);
 repeat:
 	/*
@@ -1582,9 +1890,16 @@ repeat:
 	 * match our criteria, even if we are not able to reap it yet.
 	 */
 	retval = -ECHILD;
+#ifdef CONFIG_KRG_EPM
+	if (!current->children_obj)
+#endif
 	if ((type < PIDTYPE_MAX) && (!pid || hlist_empty(&pid->tasks[type])))
 		goto end;
 
+#ifdef CONFIG_KRG_EPM
+	if (current->children_obj)
+		__krg_children_readlock(current);
+#endif
 	current->state = TASK_INTERRUPTIBLE;
 	read_lock(&tasklist_lock);
 	tsk = current;
@@ -1610,11 +1925,28 @@ repeat:
 		BUG_ON(tsk->signal != current->signal);
 	} while (tsk != current);
 	read_unlock(&tasklist_lock);
+#ifdef CONFIG_KRG_EPM
+	if (current->children_obj) {
+		/* Try all children, even remote ones but don't wait yet */
+		/* Releases children lock */
+		int tsk_result = krg_do_wait(current->children_obj, &retval,
+					     type, upid, options,
+					     infop, stat_addr, ru);
+		if (tsk_result)
+			retval = tsk_result;
+	}
+#endif
 
 	if (!retval && !(options & WNOHANG)) {
 		retval = -ERESTARTSYS;
 		if (!signal_pending(current)) {
+#ifdef CONFIG_KRG_PROC
+			up_read(&kerrighed_init_sem);
+#endif
 			schedule();
+#ifdef CONFIG_KRG_PROC
+			down_read(&kerrighed_init_sem);
+#endif
 			goto repeat;
 		}
 	}
@@ -1622,6 +1954,9 @@ repeat:
 end:
 	current->state = TASK_RUNNING;
 	remove_wait_queue(&current->signal->wait_chldexit,&wait);
+#ifdef CONFIG_KRG_PROC
+	up_read(&kerrighed_init_sem);
+#endif
 	if (infop) {
 		if (retval > 0)
 			retval = 0;
@@ -1680,7 +2015,11 @@ SYSCALL_DEFINE5(waitid, int, which, pid_t, upid, struct siginfo __user *,
 
 	if (type < PIDTYPE_MAX)
 		pid = find_get_pid(upid);
+#ifdef CONFIG_KRG_EPM
+	ret = do_wait(type, pid, upid, options, infop, NULL, ru);
+#else
 	ret = do_wait(type, pid, options, infop, NULL, ru);
+#endif
 	put_pid(pid);
 
 	/* avoid REGPARM breakage on x86: */
@@ -1712,7 +2051,17 @@ SYSCALL_DEFINE4(wait4, pid_t, upid, int __user *, stat_addr,
 		pid = find_get_pid(upid);
 	}
 
+#ifdef CONFIG_KRG_EPM
+	if (type == PIDTYPE_PGID) {
+		if (upid == 0)
+			upid = pid_vnr(pid);
+		else /* upid < 0 */
+			upid = -upid;
+	}
+	ret = do_wait(type, pid, upid, options | WEXITED, NULL, stat_addr, ru);
+#else
 	ret = do_wait(type, pid, options | WEXITED, NULL, stat_addr, ru);
+#endif
 	put_pid(pid);
 
 	/* avoid REGPARM breakage on x86: */
diff --git a/kernel/fork.c b/kernel/fork.c
index 875ffbd..7999597 100644
