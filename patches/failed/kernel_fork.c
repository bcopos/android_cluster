--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -63,6 +63,24 @@
 #include <linux/fs_struct.h>
 #include <trace/sched.h>
 #include <linux/magic.h>
+#ifdef CONFIG_KRG_KDDM
+#include <kddm/kddm_info.h>
+#endif
+#ifdef CONFIG_KRG_HOTPLUG
+#include <kerrighed/namespace.h>
+#endif
+#ifdef CONFIG_KRG_PROC
+#include <kerrighed/task.h>
+#include <kerrighed/krginit.h>
+#endif
+#ifdef CONFIG_KRG_EPM
+#include <kerrighed/signal.h>
+#include <kerrighed/children.h>
+#include <kerrighed/application.h>
+#endif
+#ifdef CONFIG_KRG_SCHED
+#include <kerrighed/scheduler/info.h>
+#endif
 
 #include <asm/pgtable.h>
 #include <asm/pgalloc.h>
@@ -99,7 +117,10 @@ int nr_processes(void)
 #ifndef __HAVE_ARCH_TASK_STRUCT_ALLOCATOR
 # define alloc_task_struct()	kmem_cache_alloc(task_struct_cachep, GFP_KERNEL)
 # define free_task_struct(tsk)	kmem_cache_free(task_struct_cachep, (tsk))
-static struct kmem_cache *task_struct_cachep;
+#ifndef CONFIG_KRG_EPM
+static
+#endif
+struct kmem_cache *task_struct_cachep;
 #endif
 
 #ifndef __HAVE_ARCH_THREAD_INFO_ALLOCATOR
@@ -120,7 +141,10 @@ static inline void free_thread_info(struct thread_info *ti)
 #endif
 
 /* SLAB cache for signal_struct structures (tsk->signal) */
-static struct kmem_cache *signal_cachep;
+#ifndef CONFIG_KRG_EPM
+static
+#endif
+struct kmem_cache *signal_cachep;
 
 /* SLAB cache for sighand_struct structures (tsk->sighand) */
 struct kmem_cache *sighand_cachep;
@@ -135,7 +159,10 @@ struct kmem_cache *fs_cachep;
 struct kmem_cache *vm_area_cachep;
 
 /* SLAB cache for mm_struct structures (tsk->mm) */
-static struct kmem_cache *mm_cachep;
+#ifndef CONFIG_KRG_MM
+static
+#endif
+struct kmem_cache *mm_cachep;
 
 void free_task(struct task_struct *tsk)
 {
@@ -218,6 +245,9 @@ static struct task_struct *dup_task_struct(struct task_struct *orig)
 
 	int err;
 
+#ifdef CONFIG_KRG_EPM
+	if (!krg_current)
+#endif
 	prepare_to_copy(orig);
 
 	tsk = alloc_task_struct();
@@ -264,7 +294,11 @@ out:
 }
 
 #ifdef CONFIG_MMU
+#ifdef CONFIG_KRG_MM
+int __dup_mmap(struct mm_struct *mm, struct mm_struct *oldmm, int anon_only)
+#else
 static int dup_mmap(struct mm_struct *mm, struct mm_struct *oldmm)
+#endif
 {
 	struct vm_area_struct *mpnt, *tmp, **pprev;
 	struct rb_node **rb_link, *rb_parent;
@@ -294,7 +328,12 @@ static int dup_mmap(struct mm_struct *mm, struct mm_struct *oldmm)
 	for (mpnt = oldmm->mmap; mpnt; mpnt = mpnt->vm_next) {
 		struct file *file;
 
+#ifdef CONFIG_KRG_MM
+		if ((mpnt->vm_flags & VM_DONTCOPY)
+		    || (anon_only && !anon_vma(mpnt))) {
+#else
 		if (mpnt->vm_flags & VM_DONTCOPY) {
+#endif
 			long pages = vma_pages(mpnt);
 			mm->total_vm -= pages;
 			vm_stat_account(mm, mpnt->vm_flags, mpnt->vm_file,
@@ -359,7 +398,11 @@ static int dup_mmap(struct mm_struct *mm, struct mm_struct *oldmm)
 		rb_parent = &tmp->vm_rb;
 
 		mm->map_count++;
+#ifdef CONFIG_KRG_MM
+		retval = copy_page_range(mm, oldmm, mpnt, anon_only);
+#else
 		retval = copy_page_range(mm, oldmm, mpnt);
+#endif
 
 		if (tmp->vm_ops && tmp->vm_ops->open)
 			tmp->vm_ops->open(tmp);
@@ -383,6 +426,14 @@ fail_nomem:
 	goto out;
 }
 
+#ifdef CONFIG_KRG_MM
+static inline int dup_mmap(struct mm_struct *mm, struct mm_struct *oldmm)
+{
+       return __dup_mmap(mm, oldmm, 0);
+}
+#endif
+
+
 static inline int mm_alloc_pgd(struct mm_struct * mm)
 {
 	mm->pgd = pgd_alloc(mm);
@@ -403,8 +454,10 @@ static inline void mm_free_pgd(struct mm_struct * mm)
 
 __cacheline_aligned_in_smp DEFINE_SPINLOCK(mmlist_lock);
 
+#ifndef CONFIG_KRG_MM
 #define allocate_mm()	(kmem_cache_alloc(mm_cachep, GFP_KERNEL))
 #define free_mm(mm)	(kmem_cache_free(mm_cachep, (mm)))
+#endif
 
 static unsigned long default_dump_filter = MMF_DUMP_FILTER_DEFAULT;
 
@@ -420,8 +473,18 @@ __setup("coredump_filter=", coredump_filter_setup);
 
 #include <linux/init_task.h>
 
-static struct mm_struct * mm_init(struct mm_struct * mm, struct task_struct *p)
+#ifndef CONFIG_KRG_MM
+static
+#endif
+struct mm_struct * mm_init(struct mm_struct * mm, struct task_struct *p)
 {
+#ifdef CONFIG_KRG_MM
+	atomic_set(&mm->mm_tasks, 1);
+#endif
+#ifdef CONFIG_KRG_EPM
+	atomic_set(&mm->mm_ltasks, 1);
+	init_rwsem(&mm->remove_sem);
+#endif
 	atomic_set(&mm->mm_users, 1);
 	atomic_set(&mm->mm_count, 1);
 	init_rwsem(&mm->mmap_sem);
@@ -429,6 +492,9 @@ static struct mm_struct * mm_init(struct mm_struct * mm, struct task_struct *p)
 	mm->flags = (current->mm) ? current->mm->flags : default_dump_filter;
 	mm->core_state = NULL;
 	mm->nr_ptes = 0;
+#ifdef CONFIG_KRG_MM
+	mm->mm_id = 0;
+#endif
 	set_mm_counter(mm, file_rss, 0);
 	set_mm_counter(mm, anon_rss, 0);
 	spin_lock_init(&mm->page_table_lock);
@@ -495,6 +561,9 @@ void mmput(struct mm_struct *mm)
 			spin_unlock(&mmlist_lock);
 		}
 		put_swap_token(mm);
+#ifdef CONFIG_KRG_EPM
+		BUG_ON(atomic_read(&mm->mm_ltasks) != 0);
+#endif
 		mmdrop(mm);
 	}
 }
@@ -555,10 +624,19 @@ void mm_release(struct task_struct *tsk, struct mm_struct *mm)
 
 	/* Get rid of any cached register state */
 	deactivate_mm(tsk, mm);
+#ifdef CONFIG_KRG_EPM
+	if (mm)
+		atomic_dec(&mm->mm_ltasks);
+#endif
 
 	/* notify parent sleeping on vfork() */
 	if (vfork_done) {
 		tsk->vfork_done = NULL;
+#ifdef CONFIG_KRG_EPM
+		if (tsk->remote_vfork_done)
+			krg_vfork_done(vfork_done);
+		else
+#endif
 		complete(vfork_done);
 	}
 
@@ -623,6 +701,9 @@ struct mm_struct *dup_mm(struct task_struct *tsk)
 	return mm;
 
 free_pt:
+#ifdef CONFIG_KRG_EPM
+	atomic_dec(&mm->mm_ltasks);
+#endif
 	mmput(mm);
 
 fail_nomem:
@@ -662,12 +743,28 @@ static int copy_mm(unsigned long clone_flags, struct task_struct * tsk)
 		return 0;
 
 	if (clone_flags & CLONE_VM) {
+#ifdef CONFIG_KRG_EPM
+		atomic_inc(&oldmm->mm_ltasks);
+#endif
 		atomic_inc(&oldmm->mm_users);
+#ifdef CONFIG_KRG_MM
+#ifdef CONFIG_KRG_EPM
+		/* Forking the ghost do not create a real new task. No need
+		 * to inc the mm_task counter */
+		if (!krg_current)
+#endif
+			KRGFCT(kh_mm_get)(oldmm);
+#endif
 		mm = oldmm;
 		goto good_mm;
 	}
 
 	retval = -ENOMEM;
+#ifdef CONFIG_KRG_MM
+	if (kh_copy_mm)
+		mm = kh_copy_mm(tsk, oldmm, clone_flags);
+	else
+#endif
 	mm = dup_mm(tsk);
 	if (!mm)
 		goto fail_nomem;
@@ -761,8 +858,29 @@ static int copy_sighand(unsigned long clone_flags, struct task_struct *tsk)
 {
 	struct sighand_struct *sig;
 
+#ifdef CONFIG_KRG_EPM
+	if (krg_current && !in_krg_do_fork())
+		/*
+		 * This is a process migration or restart: sighand_struct is
+		 * already setup.
+		 */
+		return 0;
+
+	if (!krg_current)
+#endif
 	if (clone_flags & CLONE_SIGHAND) {
+#ifdef CONFIG_KRG_EPM
+		sig = current->sighand;
+		if (sig->kddm_obj)
+			krg_sighand_writelock(sig->krg_objid);
+#endif
 		atomic_inc(&current->sighand->count);
+#ifdef CONFIG_KRG_EPM
+		if (sig->kddm_obj) {
+			krg_sighand_share(current);
+			krg_sighand_unlock(sig->krg_objid);
+		}
+#endif
 		return 0;
 	}
 	sig = kmem_cache_alloc(sighand_cachep, GFP_KERNEL);
@@ -771,6 +889,14 @@ static int copy_sighand(unsigned long clone_flags, struct task_struct *tsk)
 		return -ENOMEM;
 	atomic_set(&sig->count, 1);
 	memcpy(sig->action, current->sighand->action, sizeof(sig->action));
+#ifdef CONFIG_KRG_EPM
+	/*
+	 * Too early to allocate the KDDM object, will do it once we know the
+	 * pid.
+	 */
+	sig->krg_objid = 0;
+	sig->kddm_obj = NULL;
+#endif
 	return 0;
 }
 
@@ -784,7 +910,10 @@ void __cleanup_sighand(struct sighand_struct *sighand)
 /*
  * Initialize POSIX timer handling for a thread group.
  */
-static void posix_cpu_timers_init_group(struct signal_struct *sig)
+#ifndef CONFIG_KRG_EPM
+static
+#endif
+void posix_cpu_timers_init_group(struct signal_struct *sig)
 {
 	/* Thread group counters. */
 	thread_group_cputime_init(sig);
@@ -816,9 +945,31 @@ static int copy_signal(unsigned long clone_flags, struct task_struct *tsk)
 {
 	struct signal_struct *sig;
 
+#ifdef CONFIG_KRG_EPM
+	if (krg_current && !in_krg_do_fork()) {
+		/*
+		 * This is a process migration or restart: signal_struct is
+		 * already setup.
+		 */
+		tsk->signal->curr_target = tsk;
+		return 0;
+	}
+
+	if (!krg_current)
+#endif
 	if (clone_flags & CLONE_THREAD) {
+#ifdef CONFIG_KRG_EPM
+		if (current->signal->kddm_obj)
+			krg_signal_writelock(current->signal);
+#endif
 		atomic_inc(&current->signal->count);
 		atomic_inc(&current->signal->live);
+#ifdef CONFIG_KRG_EPM
+		if (current->signal->kddm_obj) {
+			krg_signal_share(current->signal);
+			krg_signal_unlock(current->signal);
+		}
+#endif
 		return 0;
 	}
 
@@ -858,8 +1009,14 @@ static int copy_signal(unsigned long clone_flags, struct task_struct *tsk)
 	sig->sum_sched_runtime = 0;
 	taskstats_tgid_init(sig);
 
+#ifdef CONFIG_KRG_EPM
+	if (!krg_current)
+#endif
 	task_lock(current->group_leader);
 	memcpy(sig->rlim, current->signal->rlim, sizeof sig->rlim);
+#ifdef CONFIG_KRG_EPM
+	if (!krg_current)
+#endif
 	task_unlock(current->group_leader);
 
 	posix_cpu_timers_init_group(sig);
@@ -868,6 +1025,14 @@ static int copy_signal(unsigned long clone_flags, struct task_struct *tsk)
 
 	tty_audit_fork(sig);
 
+#ifdef CONFIG_KRG_EPM
+	/*
+	 * Too early to allocate the KDDM object, will do it once the tgid is
+	 * known.
+	 */
+	sig->krg_objid = 0;
+	sig->kddm_obj = NULL;
+#endif
 	return 0;
 }
 
@@ -881,11 +1046,20 @@ void __cleanup_signal(struct signal_struct *sig)
 static void cleanup_signal(struct task_struct *tsk)
 {
 	struct signal_struct *sig = tsk->signal;
+#ifdef CONFIG_KRG_EPM
+	struct signal_struct *locked_sig;
+#endif
 
+#ifdef CONFIG_KRG_EPM
+	locked_sig = krg_signal_exit(sig);
+#endif
 	atomic_dec(&sig->live);
 
 	if (atomic_dec_and_test(&sig->count))
 		__cleanup_signal(sig);
+#ifdef CONFIG_KRG_EPM
+	krg_signal_unlock(locked_sig);
+#endif
 }
 
 static void copy_flags(unsigned long clone_flags, struct task_struct *p)
@@ -943,7 +1117,10 @@ static void posix_cpu_timers_init(struct task_struct *tsk)
  * parts of the process environment (as per the clone
  * flags). The actual kick-off is left to the caller.
  */
-static struct task_struct *copy_process(unsigned long clone_flags,
+#ifndef CONFIG_KRG_EPM
+static
+#endif
+struct task_struct *copy_process(unsigned long clone_flags,
 					unsigned long stack_start,
 					struct pt_regs *regs,
 					unsigned long stack_size,
@@ -951,6 +1128,9 @@ static struct task_struct *copy_process(unsigned long clone_flags,
 					struct pid *pid,
 					int trace)
 {
+#ifdef CONFIG_KRG_HOTPLUG
+	int saved_create_krg_ns;
+#endif
 	int retval;
 	struct task_struct *p;
 	int cgroup_callbacks_done = 0;
@@ -973,6 +1153,11 @@ static struct task_struct *copy_process(unsigned long clone_flags,
 	if ((clone_flags & CLONE_SIGHAND) && !(clone_flags & CLONE_VM))
 		return ERR_PTR(-EINVAL);
 
+#ifdef CONFIG_KRG_HOTPLUG
+	saved_create_krg_ns = current->create_krg_ns;
+	current->create_krg_ns = can_create_krg_ns(clone_flags);
+#endif
+
 	retval = security_task_create(clone_flags);
 	if (retval)
 		goto fork_out;
@@ -982,6 +1167,10 @@ static struct task_struct *copy_process(unsigned long clone_flags,
 	if (!p)
 		goto fork_out;
 
+#ifdef CONFIG_KRG_HOTPLUG
+	p->create_krg_ns = 0;
+#endif
+
 	rt_mutex_init_task(p);
 
 #ifdef CONFIG_PROVE_LOCKING
@@ -1016,6 +1205,9 @@ static struct task_struct *copy_process(unsigned long clone_flags,
 		goto bad_fork_cleanup_put_domain;
 
 	p->did_exec = 0;
+#ifdef CONFIG_KRG_EPM
+	if (!krg_current)
+#endif
 	delayacct_tsk_init(p);	/* Must remain after dup_task_struct() */
 	copy_flags(clone_flags, p);
 	INIT_LIST_HEAD(&p->children);
@@ -1024,6 +1216,9 @@ static struct task_struct *copy_process(unsigned long clone_flags,
 	p->rcu_read_lock_nesting = 0;
 	p->rcu_flipctr_idx = 0;
 #endif /* #ifdef CONFIG_PREEMPT_RCU */
+#ifdef CONFIG_KRG_EPM
+	if (!krg_current)
+#endif
 	p->vfork_done = NULL;
 	spin_lock_init(&p->alloc_lock);
 
@@ -1040,8 +1235,14 @@ static struct task_struct *copy_process(unsigned long clone_flags,
 
 	p->default_timer_slack_ns = current->timer_slack_ns;
 
+#ifdef CONFIG_KRG_EPM
+	if (!krg_current || in_krg_do_fork()) {
+#endif
 	task_io_accounting_init(&p->ioac);
 	acct_clear_integrals(p);
+#ifdef CONFIG_KRG_EPM
+	}
+#endif
 
 	posix_cpu_timers_init(p);
 
@@ -1095,8 +1296,23 @@ static struct task_struct *copy_process(unsigned long clone_flags,
 	/* Perform scheduler related setup. Assign this task to a CPU. */
 	sched_fork(p, clone_flags);
 
+#ifdef CONFIG_KRG_CAP
+	krg_cap_fork(p, clone_flags);
+#endif /* CONFIG_KRG_CAP */
+
+#ifdef CONFIG_KRG_KDDM
+	if (!kh_copy_kddm_info)
+		p->kddm_info = NULL;
+	else if ((retval = kh_copy_kddm_info(clone_flags, p)))
+		goto bad_fork_cleanup_policy;
+#endif /* CONFIG_KRG_KDDM */
+
 	if ((retval = audit_alloc(p)))
+#ifdef CONFIG_KRG_KDDM
+		goto bad_fork_cleanup_kddm_info;
+#else
 		goto bad_fork_cleanup_policy;
+#endif /* CONFIG_KRG_KDDM */
 	/* copy all the process information */
 	if ((retval = copy_semundo(clone_flags, p)))
 		goto bad_fork_cleanup_audit;
@@ -1118,6 +1334,9 @@ static struct task_struct *copy_process(unsigned long clone_flags,
 	if (retval)
 		goto bad_fork_cleanup_io;
 
+#ifdef CONFIG_KRG_EPM
+	if (!krg_current)
+#endif
 	if (pid != &init_struct_pid) {
 		retval = -ENOMEM;
 		pid = alloc_pid(p->nsproxy->pid_ns);
@@ -1148,6 +1367,9 @@ static struct task_struct *copy_process(unsigned long clone_flags,
 	/*
 	 * Clear TID on mm_release()?
 	 */
+#ifdef CONFIG_KRG_EPM
+	if (!krg_current || in_krg_do_fork())
+#endif
 	p->clear_child_tid = (clone_flags & CLONE_CHILD_CLEARTID) ? child_tidptr: NULL;
 #ifdef CONFIG_FUTEX
 	p->robust_list = NULL;
@@ -1160,6 +1382,9 @@ static struct task_struct *copy_process(unsigned long clone_flags,
 	/*
 	 * sigaltstack should be cleared when sharing the same VM
 	 */
+#ifdef CONFIG_KRG_EPM
+	if (!krg_current)
+#endif
 	if ((clone_flags & (CLONE_VM|CLONE_VFORK)) == CLONE_VM)
 		p->sas_ss_sp = p->sas_ss_size = 0;
 
@@ -1174,9 +1399,22 @@ static struct task_struct *copy_process(unsigned long clone_flags,
 	clear_all_latency_tracing(p);
 
 	/* ok, now we should be set up.. */
+#ifdef CONFIG_KRG_EPM
+	if (!krg_current) {
+#endif
 	p->exit_signal = (clone_flags & CLONE_THREAD) ? -1 : (clone_flags & CSIGNAL);
 	p->pdeath_signal = 0;
 	p->exit_state = 0;
+#ifdef CONFIG_KRG_EPM
+	} else {
+		p->exit_signal = clone_flags & CSIGNAL;
+		if (in_krg_do_fork()) {
+			/* Remote clone */
+			p->pdeath_signal = 0;
+			p->exit_state = 0;
+		}
+	}
+#endif
 
 	/*
 	 * Ok, make it visible to the rest of the system.
@@ -1191,6 +1429,39 @@ static struct task_struct *copy_process(unsigned long clone_flags,
 	cgroup_fork_callbacks(p);
 	cgroup_callbacks_done = 1;
 
+#ifdef CONFIG_KRG_EPM
+	krg_sighand_alloc(p, clone_flags);
+	krg_signal_alloc(p, pid, clone_flags);
+
+	if (!krg_current) {
+		retval = krg_copy_application(p);
+		if (retval)
+			goto bad_fork_free_graph;
+	}
+
+	retval = krg_children_prepare_fork(p, pid, clone_flags);
+	if (retval)
+		goto bad_fork_cleanup_application;
+#endif
+#ifdef CONFIG_KRG_PROC
+	retval = krg_task_alloc(p, pid);
+	if (retval)
+#ifdef CONFIG_KRG_EPM
+		goto bad_fork_cleanup_children;
+#else
+		goto bad_fork_free_graph;
+#endif
+#endif
+#ifdef CONFIG_KRG_SCHED
+	retval = krg_sched_info_copy(p);
+	if (retval)
+#ifdef CONFIG_KRG_PROC
+		goto bad_fork_free_krg_task;
+#else
+		goto bad_fork_free_graph;
+#endif
+#endif /* CONFIG_KRG_SCHED */
+
 	/* Need tasklist lock for parent etc handling! */
 	write_lock_irq(&tasklist_lock);
 
@@ -1217,6 +1488,17 @@ static struct task_struct *copy_process(unsigned long clone_flags,
 		p->real_parent = current;
 		p->parent_exec_id = current->self_exec_id;
 	}
+#ifdef CONFIG_KRG_EPM
+	if (!krg_current
+	    && p->real_parent == baby_sitter && !p->parent_children_obj)
+		/*
+		 * parent died (remotely) and current is still attached to
+		 * baby_sitter. p having no parent_children_obj pointer, p must
+		 * be attached to a real local process. Fortunately this can
+		 * only be the local child reaper.
+		 */
+		p->real_parent = task_active_pid_ns(current)->child_reaper;
+#endif /* CONFIG_KRG_EPM */
 
 	spin_lock(&current->sighand->siglock);
 
@@ -1229,20 +1511,51 @@ static struct task_struct *copy_process(unsigned long clone_flags,
 	 * thread can't slip out of an OOM kill (or normal SIGKILL).
  	 */
 	recalc_sigpending();
+#ifdef CONFIG_KRG_EPM
+	/* Only check if inside a remote clone() */
+	if (!krg_current || in_krg_do_fork())
+#endif
 	if (signal_pending(current)) {
 		spin_unlock(&current->sighand->siglock);
 		write_unlock_irq(&tasklist_lock);
 		retval = -ERESTARTNOINTR;
+#if defined(CONFIG_KRG_SCHED)
+		goto bad_fork_free_krg_sched;
+#elif defined(CONFIG_KRG_PROC)
+		goto bad_fork_free_krg_task;
+#else
 		goto bad_fork_free_graph;
+#endif
 	}
 
+#ifdef CONFIG_KRG_EPM
+	retval = krg_children_fork(p, pid, clone_flags);
+	if (retval) {
+		spin_unlock(&current->sighand->siglock);
+		write_unlock_irq(&tasklist_lock);
+#ifdef CONFIG_KRG_SCHED
+		goto bad_fork_free_krg_sched;
+#else
+		goto bad_fork_free_krg_task;
+#endif
+	}
+#endif /* CONFIG_KRG_EPM */
+#ifdef CONFIG_KRG_EPM
+	if (!krg_current || !thread_group_leader(krg_current))
+#endif
 	if (clone_flags & CLONE_THREAD) {
 		p->group_leader = current->group_leader;
 		list_add_tail_rcu(&p->thread_group, &p->group_leader->thread_group);
 	}
 
 	if (likely(p->pid)) {
+#ifdef CONFIG_KRG_EPM
+		if (p->real_parent != baby_sitter)
+#endif
 		list_add_tail(&p->sibling, &p->real_parent->children);
+#ifdef CONFIG_KRG_EPM
+		attach_pid(p, PIDTYPE_PID, pid);
+#endif
 		tracehook_finish_clone(p, clone_flags, trace);
 
 		if (thread_group_leader(p)) {
@@ -1257,20 +1570,52 @@ static struct task_struct *copy_process(unsigned long clone_flags,
 			list_add_tail_rcu(&p->tasks, &init_task.tasks);
 			__get_cpu_var(process_counts)++;
 		}
+#ifndef CONFIG_KRG_EPM
 		attach_pid(p, PIDTYPE_PID, pid);
+#endif
 		nr_threads++;
 	}
+#ifdef CONFIG_KRG_PROC
+	krg_task_fill(p, clone_flags);
+#endif
 
 	total_forks++;
 	spin_unlock(&current->sighand->siglock);
 	write_unlock_irq(&tasklist_lock);
+#ifdef CONFIG_KRG_PROC
+	krg_task_commit(p);
+#endif
+#ifdef CONFIG_KRG_EPM
+	krg_children_commit_fork(p);
+#endif
 	proc_fork_connector(p);
 	cgroup_post_fork(p);
+#ifdef CONFIG_KRG_HOTPLUG
+	current->create_krg_ns = saved_create_krg_ns;
+#endif
 	return p;
 
+#ifdef CONFIG_KRG_SCHED
+bad_fork_free_krg_sched:
+	krg_sched_info_free(p);
+#endif
+#ifdef CONFIG_KRG_PROC
+bad_fork_free_krg_task:
+	krg_task_abort(p);
+#endif
+#ifdef CONFIG_KRG_EPM
+bad_fork_cleanup_children:
+	krg_children_abort_fork(p);
+bad_fork_cleanup_application:
+	if (!krg_current)
+		krg_exit_application(p);
+#endif
 bad_fork_free_graph:
 	ftrace_graph_exit_task(p);
 bad_fork_free_pid:
+#ifdef CONFIG_KRG_EPM
+	if (!krg_current)
+#endif
 	if (pid != &init_struct_pid)
 		free_pid(pid);
 bad_fork_cleanup_io:
@@ -1278,12 +1623,31 @@ bad_fork_cleanup_io:
 bad_fork_cleanup_namespaces:
 	exit_task_namespaces(p);
 bad_fork_cleanup_mm:
+#ifdef CONFIG_KRG_MM
+	if (p->mm && p->mm->mm_id && (clone_flags & CLONE_VM))
+#ifdef CONFIG_KRG_EPM
+		if (!krg_current)
+#endif
+			KRGFCT(kh_mm_release)(p->mm, 1);
+#endif
+#ifdef CONFIG_KRG_EPM
+	if (p->mm)
+		atomic_dec(&p->mm->mm_ltasks);
+#endif
 	if (p->mm)
 		mmput(p->mm);
 bad_fork_cleanup_signal:
+#ifdef CONFIG_KRG_EPM
+	if (!krg_current || in_krg_do_fork())
+#endif
 	cleanup_signal(p);
 bad_fork_cleanup_sighand:
+#ifdef CONFIG_KRG_EPM
+	if (!krg_current || in_krg_do_fork())
+		krg_sighand_cleanup(p->sighand);
+#else
 	__cleanup_sighand(p->sighand);
+#endif /* CONFIG_KRG_EPM */
 bad_fork_cleanup_fs:
 	exit_fs(p); /* blocking */
 bad_fork_cleanup_files:
@@ -1292,12 +1656,20 @@ bad_fork_cleanup_semundo:
 	exit_sem(p);
 bad_fork_cleanup_audit:
 	audit_free(p);
+#ifdef CONFIG_KRG_KDDM
+bad_fork_cleanup_kddm_info:
+	if (p->kddm_info)
+		kmem_cache_free(kddm_info_cachep, p->kddm_info);
+#endif
 bad_fork_cleanup_policy:
 #ifdef CONFIG_NUMA
 	mpol_put(p->mempolicy);
 bad_fork_cleanup_cgroup:
 #endif
 	cgroup_exit(p, cgroup_callbacks_done);
+#ifdef CONFIG_KRG_EPM
+	if (!krg_current)
+#endif
 	delayacct_tsk_free(p);
 	if (p->binfmt)
 		module_put(p->binfmt->module);
@@ -1310,6 +1682,9 @@ bad_fork_cleanup_count:
 bad_fork_free:
 	free_task(p);
 fork_out:
+#ifdef CONFIG_KRG_HOTPLUG
+	current->create_krg_ns = saved_create_krg_ns;
+#endif
 	return ERR_PTR(retval);
 }
 
@@ -1387,6 +1762,20 @@ long do_fork(unsigned long clone_flags,
 	if (likely(user_mode(regs)))
 		trace = tracehook_prepare_clone(clone_flags);
 
+#ifdef CONFIG_KRG_EPM
+#ifdef CONFIG_KRG_CAP
+	nr = 0;
+	if (can_use_krg_cap(current, CAP_DISTANT_FORK))
+#endif
+		nr = krg_do_fork(clone_flags, stack_start, regs, stack_size,
+				 parent_tidptr, child_tidptr, trace);
+	if (nr > 0)
+		return nr;
+	/* Give a chance to local fork */
+#endif /* CONFIG_KRG_EPM */
+#ifdef CONFIG_KRG_PROC
+	down_read(&kerrighed_init_sem);
+#endif
 	p = copy_process(clone_flags, stack_start, regs, stack_size,
 			 child_tidptr, NULL, trace);
 	/*
@@ -1405,6 +1794,9 @@ long do_fork(unsigned long clone_flags,
 
 		if (clone_flags & CLONE_VFORK) {
 			p->vfork_done = &vfork;
+#ifdef CONFIG_KRG_EPM
+			p->remote_vfork_done = 0;
+#endif
 			init_completion(&vfork);
 		}
 
@@ -1442,6 +1834,9 @@ long do_fork(unsigned long clone_flags,
 	} else {
 		nr = PTR_ERR(p);
 	}
+#ifdef CONFIG_KRG_PROC
+	up_read(&kerrighed_init_sem);
+#endif
 	return nr;
 }
 
@@ -1608,9 +2003,16 @@ SYSCALL_DEFINE1(unshare, unsigned long, unshare_flags)
 	struct files_struct *fd, *new_fd = NULL;
 	struct nsproxy *new_nsproxy = NULL;
 	int do_sysvsem = 0;
+#ifdef CONFIG_KRG_HOTPLUG
+	int saved_create_krg_ns;
+#endif
 
 	check_unshare_flags(&unshare_flags);
 
+#ifdef CONFIG_KRG_HOTPLUG
+	saved_create_krg_ns = current->create_krg_ns;
+	current->create_krg_ns = 0;
+#endif
 	/* Return -EINVAL for all unsupported flags */
 	err = -EINVAL;
 	if (unshare_flags & ~(CLONE_THREAD|CLONE_FS|CLONE_NEWNS|CLONE_SIGHAND|
@@ -1705,6 +2107,9 @@ bad_unshare_cleanup_fs:
 
 bad_unshare_cleanup_thread:
 bad_unshare_out:
+#ifdef CONFIG_KRG_HOTPLUG
+	current->create_krg_ns = saved_create_krg_ns;
+#endif
 	return err;
 }
 
diff --git a/kernel/futex.c b/kernel/futex.c
index d546b2d..bc9d93f 100644
