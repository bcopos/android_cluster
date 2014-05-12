--- a/kernel/sched.c
+++ b/kernel/sched.c
@@ -73,6 +73,17 @@
 #include <linux/ctype.h>
 #include <linux/ftrace.h>
 #include <trace/sched.h>
+#ifdef CONFIG_KRG_PROC
+#include <net/krgrpc/rpc.h>
+#include <net/krgrpc/rpcid.h>
+#include <kerrighed/remote_syscall.h>
+#endif
+#ifdef CONFIG_KRG_EPM
+#include <kerrighed/ghost.h>
+#endif
+#ifdef CONFIG_KRG_SCHED
+#include <kerrighed/scheduler/hooks.h>
+#endif
 
 #include <asm/tlb.h>
 #include <asm/irq_regs.h>
@@ -2324,6 +2335,13 @@ static int sched_balance_self(int cpu, int flag)
 
 #endif /* CONFIG_SMP */
 
+#if defined(CONFIG_KRG_SCHED) && defined(CONFIG_MODULE_HOOK)
+struct module_hook_desc kmh_process_on;
+EXPORT_SYMBOL(kmh_process_on);
+struct module_hook_desc kmh_process_off;
+EXPORT_SYMBOL(kmh_process_off);
+#endif
+
 /***
  * try_to_wake_up - wake up a thread
  * @p: the to-be-woken-up thread
@@ -2426,6 +2444,9 @@ out_activate:
 		schedstat_inc(p, se.nr_wakeups_remote);
 	activate_task(rq, p, 1);
 	success = 1;
+#if defined(CONFIG_KRG_SCHED) && defined(CONFIG_MODULE_HOOK)
+	module_hook_call(&kmh_process_on, (unsigned long)p);
+#endif
 
 	/*
 	 * Only attribute actual wakeups done by this task.
@@ -2477,6 +2498,9 @@ int wake_up_state(struct task_struct *p, unsigned int state)
  */
 static void __sched_fork(struct task_struct *p)
 {
+#ifdef CONFIG_KRG_EPM
+	if (!krg_current || in_krg_do_fork()) {
+#endif
 	p->se.exec_start		= 0;
 	p->se.sum_exec_runtime		= 0;
 	p->se.prev_sum_exec_runtime	= 0;
@@ -2496,6 +2520,9 @@ static void __sched_fork(struct task_struct *p)
 	p->se.slice_max			= 0;
 	p->se.wait_max			= 0;
 #endif
+#ifdef CONFIG_KRG_EPM
+	}
+#endif
 
 	INIT_LIST_HEAD(&p->rt.run_list);
 	p->se.on_rq = 0;
@@ -2536,6 +2563,9 @@ void sched_fork(struct task_struct *p, int clone_flags)
 		p->sched_class = &fair_sched_class;
 
 #if defined(CONFIG_SCHEDSTATS) || defined(CONFIG_TASK_DELAY_ACCT)
+#ifdef CONFIG_KRG_EPM
+	if (!krg_current || in_krg_do_fork())
+#endif
 	if (likely(sched_info_on()))
 		memset(&p->sched_info, 0, sizeof(p->sched_info));
 #endif
@@ -2579,6 +2609,9 @@ void wake_up_new_task(struct task_struct *p, unsigned long clone_flags)
 		p->sched_class->task_new(rq, p);
 		inc_nr_running(rq);
 	}
+#if defined(CONFIG_KRG_SCHED) && defined(CONFIG_MODULE_HOOK)
+	module_hook_call(&kmh_process_on, (unsigned long)p);
+#endif
 	trace_sched_wakeup_new(rq, p, 1);
 	check_preempt_curr(rq, p, 0);
 #ifdef CONFIG_SMP
@@ -2817,6 +2850,9 @@ unsigned long nr_running(void)
 
 	return sum;
 }
+#ifdef CONFIG_KRG_SCHED
+EXPORT_SYMBOL(nr_running);
+#endif
 
 unsigned long nr_uninterruptible(void)
 {
@@ -5013,7 +5049,14 @@ asmlinkage void __sched __schedule(void)
 	unsigned long *switch_count;
 	struct rq *rq;
 	int cpu;
+#ifdef CONFIG_KRG_EPM
+	struct task_struct *krg_cur;
+#endif
 
+#ifdef CONFIG_KRG_EPM
+	krg_cur = krg_current;
+	krg_current = NULL;
+#endif
 	cpu = smp_processor_id();
 	rq = cpu_rq(cpu);
 	rcu_qsctr_inc(cpu);
@@ -5036,7 +5079,14 @@ need_resched_nonpreemptible:
 		if (unlikely(signal_pending_state(prev->state, prev)))
 			prev->state = TASK_RUNNING;
 		else
+#if defined(CONFIG_KRG_SCHED) && defined(CONFIG_MODULE_HOOK)
+		{
+			module_hook_call(&kmh_process_off, (unsigned long)prev);
+#endif
 			deactivate_task(rq, prev, 1);
+#if defined(CONFIG_KRG_SCHED) && defined(CONFIG_MODULE_HOOK)
+		}
+#endif
 		switch_count = &prev->nvcsw;
 	}
 
@@ -5070,6 +5120,9 @@ need_resched_nonpreemptible:
 
 	if (unlikely(reacquire_kernel_lock(current) < 0))
 		goto need_resched_nonpreemptible;
+#ifdef CONFIG_KRG_EPM
+	krg_current = krg_cur;
+#endif
 }
 
 asmlinkage void __sched schedule(void)
@@ -5954,6 +6007,52 @@ int sched_setscheduler_nocheck(struct task_struct *p, int policy,
 	return __sched_setscheduler(p, policy, param, false);
 }
 
+#ifdef CONFIG_KRG_PROC
+struct setscheduler_msg {
+	int policy;
+	struct sched_param param;
+};
+
+static
+int handle_sched_setscheduler(struct rpc_desc *desc, void *_msg, size_t size)
+{
+	struct setscheduler_msg msg;
+	struct pid *pid;
+	const struct cred *old_cred;
+	struct task_struct *p;
+	int retval;
+
+	pid = krg_handle_remote_syscall_begin(desc, _msg, size,
+					      &msg, &old_cred);
+	if (IS_ERR(pid)) {
+		retval = PTR_ERR(pid);
+		goto out;
+	}
+
+	rcu_read_lock();
+	p = pid_task(pid, PIDTYPE_PID);
+	BUG_ON(!p);
+	retval = sched_setscheduler(p, msg.policy, &msg.param);
+	rcu_read_unlock();
+
+	krg_handle_remote_syscall_end(pid, old_cred);
+
+out:
+	return retval;
+}
+
+static
+int krg_sched_setscheduler(pid_t pid, int policy, struct sched_param *param)
+{
+	struct setscheduler_msg msg;
+
+	msg.policy = policy;
+	msg.param = *param;
+	return krg_remote_syscall_simple(PROC_SCHED_SETSCHEDULER, pid,
+					 &msg, sizeof(msg));
+}
+#endif /* CONFIG_KRG_PROC */
+
 static int
 do_sched_setscheduler(pid_t pid, int policy, struct sched_param __user *param)
 {
@@ -5972,6 +6071,10 @@ do_sched_setscheduler(pid_t pid, int policy, struct sched_param __user *param)
 	if (p != NULL)
 		retval = sched_setscheduler(p, policy, &lparam);
 	rcu_read_unlock();
+#ifdef CONFIG_KRG_PROC
+	if (!p)
+		retval = krg_sched_setscheduler(pid, policy, &lparam);
+#endif
 
 	return retval;
 }
@@ -6002,6 +6105,36 @@ SYSCALL_DEFINE2(sched_setparam, pid_t, pid, struct sched_param __user *, param)
 	return do_sched_setscheduler(pid, -1, param);
 }
 
+#ifdef CONFIG_KRG_PROC
+static
+int handle_sched_getscheduler(struct rpc_desc *desc, void *msg, size_t size)
+{
+	struct pid *pid;
+	const struct cred *old_cred;
+	int retval;
+
+	pid = krg_handle_remote_syscall_begin(desc, msg, size,
+					      NULL, &old_cred);
+	if (IS_ERR(pid)) {
+		retval = PTR_ERR(pid);
+		goto out;
+	}
+
+	retval = sys_sched_getscheduler(pid_vnr(pid));
+
+	krg_handle_remote_syscall_end(pid, old_cred);
+
+out:
+	return retval;
+}
+
+static int krg_sched_getscheduler(pid_t pid)
+{
+	return krg_remote_syscall_simple(PROC_SCHED_GETSCHEDULER, pid,
+					 NULL, 0);
+}
+#endif /* CONFIG_KRG_PROC */
+
 /**
  * sys_sched_getscheduler - get the policy (scheduling class) of a thread
  * @pid: the pid in question.
@@ -6023,9 +6156,81 @@ SYSCALL_DEFINE1(sched_getscheduler, pid_t, pid)
 			retval = p->policy;
 	}
 	read_unlock(&tasklist_lock);
+#ifdef CONFIG_KRG_PROC
+	if (!p)
+		retval = krg_sched_getscheduler(pid);
+#endif
 	return retval;
 }
 
+#ifdef CONFIG_KRG_PROC
+static
+int handle_sched_getparam(struct rpc_desc *desc, void *msg, size_t size)
+{
+	struct pid *pid;
+	struct sched_param param;
+	const struct cred *old_cred;
+	int retval, err;
+
+	pid = krg_handle_remote_syscall_begin(desc, msg, size,
+					      NULL, &old_cred);
+	if (IS_ERR(pid)) {
+		retval = PTR_ERR(pid);
+		goto out;
+	}
+
+	retval = sys_sched_getparam(pid_vnr(pid), &param);
+	if (retval)
+		goto out_end;
+
+	err = rpc_pack_type(desc, param);
+	if (err) {
+		rpc_cancel(desc);
+		retval = err;
+	}
+
+out_end:
+	krg_handle_remote_syscall_end(pid, old_cred);
+
+out:
+	return retval;
+}
+
+static int krg_sched_getparam(pid_t pid, struct sched_param *param)
+{
+	struct rpc_desc *desc;
+	int res, r;
+
+	desc = krg_remote_syscall_begin(PROC_SCHED_GETPARAM, pid, NULL, 0);
+	if (IS_ERR(desc)) {
+		r = PTR_ERR(desc);
+		goto out;
+	}
+
+	r = rpc_unpack_type(desc, res);
+	if (r)
+		goto err_cancel;
+	r = res;
+	if (r)
+		goto out_end;
+	r = rpc_unpack_type(desc, *param);
+	if (r)
+		goto err_cancel;
+
+out_end:
+	krg_remote_syscall_end(desc, pid);
+
+out:
+	return r;
+
+err_cancel:
+	if (r > 0)
+		r = -EPIPE;
+	rpc_cancel(desc);
+	goto out_end;
+}
+#endif /* CONFIG_KRG_PROC */
+
 /**
  * sys_sched_getscheduler - get the RT priority of a thread
  * @pid: the pid in question.
@@ -6042,6 +6247,15 @@ SYSCALL_DEFINE2(sched_getparam, pid_t, pid, struct sched_param __user *, param)
 
 	read_lock(&tasklist_lock);
 	p = find_process_by_pid(pid);
+#ifdef CONFIG_KRG_PROC
+	if (!p) {
+		read_unlock(&tasklist_lock);
+		retval = krg_sched_getparam(pid, &lp);
+		if (retval)
+			goto out_nounlock;
+		goto copy;
+	}
+#endif
 	retval = -ESRCH;
 	if (!p)
 		goto out_unlock;
@@ -6053,11 +6267,17 @@ SYSCALL_DEFINE2(sched_getparam, pid_t, pid, struct sched_param __user *, param)
 	lp.sched_priority = p->rt_priority;
 	read_unlock(&tasklist_lock);
 
+#ifdef CONFIG_KRG_PROC
+copy:
+#endif
 	/*
 	 * This one might sleep, we cannot do it with a spinlock held ...
 	 */
 	retval = copy_to_user(param, &lp, sizeof(*param)) ? -EFAULT : 0;
 
+#ifdef CONFIG_KRG_PROC
+out_nounlock:
+#endif
 	return retval;
 
 out_unlock:
@@ -6324,8 +6544,15 @@ EXPORT_SYMBOL(cond_resched_softirq);
  */
 void __sched yield(void)
 {
+#ifdef CONFIG_KRG_EPM
+	struct task_struct *krg_cur = krg_current;
+	krg_current = NULL;
+#endif
 	set_current_state(TASK_RUNNING);
 	sys_sched_yield();
+#ifdef CONFIG_KRG_EPM
+	krg_current = krg_cur;
+#endif
 }
 EXPORT_SYMBOL(yield);
 
@@ -6466,6 +6693,88 @@ out_unlock:
 	return retval;
 }
 
+#ifdef CONFIG_KRG_EPM
+
+struct epm_action;
+
+struct task_sched_params {
+	int policy, rt_prio, static_prio;
+};
+
+int export_sched(struct epm_action *action,
+		 ghost_t *ghost, struct task_struct *task)
+{
+	struct task_sched_params params;
+	unsigned long flags;
+	struct rq *rq;
+	int err = 0;
+
+	rq = task_rq_lock(task, &flags);
+	params.policy = task->policy;
+	params.rt_prio = task->rt_priority;
+	params.static_prio = task->static_prio;
+	/* Group scheduling is not supported yet */
+#if defined(CONFIG_GROUP_SCHED) && !defined(CONFIG_USER_SCHED)
+	if (task_group(task) != &init_task_group)
+		err = -EPERM;
+#endif
+	task_rq_unlock(rq, &flags);
+
+	if (!err)
+		err = ghost_write(ghost, &params, sizeof(params));
+
+	return err;
+}
+
+int import_sched(struct epm_action *action,
+		 ghost_t *ghost, struct task_struct *task)
+{
+	struct task_sched_params params;
+	int cpu;
+	int err;
+
+	err = ghost_read(ghost, &params, sizeof(params));
+	if (err)
+		goto out;
+
+	/* Mostly bug-catchers inits */
+	INIT_LIST_HEAD(&task->rt.run_list);
+	task->rt.back = NULL;
+#ifdef CONFIG_RT_GROUP_SCHED
+	task->rt.parent = NULL;
+	task->rt.rt_rq = NULL;
+	task->rt.my_q = NULL;
+#endif
+	/* Checked by __setscheduler() */
+	task->se.on_rq = 0;
+	INIT_LIST_HEAD(&task->se.group_node);
+#ifdef CONFIG_FAIR_GROUP_SCHED
+	task->se.parent = NULL;
+	task->se.cfs_rq = NULL;
+	task->se.my_q = NULL;
+#endif
+	cpu = get_cpu();
+	__set_task_cpu(task, cpu);
+	put_cpu();
+
+	task->static_prio = params.static_prio;
+	__setscheduler(NULL, task, params.policy, params.rt_prio);
+
+out:
+	return err;
+}
+
+#endif /* CONFIG_KRG_EPM */
+
+#ifdef CONFIG_KRG_PROC
+void remote_sched_init(void)
+{
+	rpc_register_int(PROC_SCHED_SETSCHEDULER, handle_sched_setscheduler, 0);
+	rpc_register_int(PROC_SCHED_GETPARAM, handle_sched_getparam, 0);
+	rpc_register_int(PROC_SCHED_GETSCHEDULER, handle_sched_getscheduler, 0);
+}
+#endif /* CONFIG_KRG_PROC */
+
 static const char stat_nam[] = TASK_STATE_TO_CHAR_STR;
 
 void sched_show_task(struct task_struct *p)
@@ -6908,6 +7217,9 @@ void sched_idle_next(void)
 
 	update_rq_clock(rq);
 	activate_task(rq, p, 0);
+#if defined(CONFIG_KRG_SCHED) && defined(CONFIG_MODULE_HOOK)
+	module_hook_call(&kmh_process_on, (unsigned long)p);
+#endif
 
 	spin_unlock_irqrestore(&rq->lock, flags);
 }
diff --git a/kernel/signal.c b/kernel/signal.c
index d803473..c325ff0 100644
