--- a/kernel/ptrace.c
+++ b/kernel/ptrace.c
@@ -22,7 +22,89 @@
 #include <linux/pid_namespace.h>
 #include <linux/syscalls.h>
 #include <linux/uaccess.h>
+#ifdef CONFIG_KRG_EPM
+#include <kerrighed/action.h>
+#include <kerrighed/krginit.h>
+#include <kerrighed/children.h>
+#include <kerrighed/krg_exit.h>
+#endif
+
+
+#ifdef CONFIG_KRG_EPM
+/* Helpers to make ptrace and migration mutually exclusive */
+
+int krg_ptrace_link(struct task_struct *task, struct task_struct *tracer)
+{
+	struct task_struct *parent;
+	int retval;
+
+	/* Lock to-be-ptraced task on this node */
+	retval = krg_action_disable(task, EPM_MIGRATE, 0);
+	if (retval)
+		goto bad_task;
+	/* Lock tracer on this node */
+	retval = krg_action_disable(tracer, EPM_MIGRATE, 0);
+	if (retval)
+		goto bad_tracer;
+	/* Lock parent on this node */
+	retval = -EPERM;
+	parent = task->parent;
+	if (parent == baby_sitter)
+		goto bad_parent;
+	if (!is_container_init(parent) && parent != tracer) {
+		retval = krg_action_disable(parent, EPM_MIGRATE, 0);
+		if (retval)
+			goto bad_parent;
+	}
+
+	return 0;
+
+bad_parent:
+	krg_action_enable(tracer, EPM_MIGRATE, 0);
+bad_tracer:
+	krg_action_enable(task, EPM_MIGRATE, 0);
+bad_task:
+	return retval;
+}
+
+/* Assumes at least read_lock on tasklist */
+/* Called with write_lock_irq on tasklist */
+void krg_ptrace_unlink(struct task_struct *task)
+{
+	BUG_ON(task->real_parent == baby_sitter);
+	if (!is_container_init(task->real_parent)
+	    && task->real_parent != task->parent)
+		krg_action_enable(task->real_parent, EPM_MIGRATE, 0);
+	BUG_ON(task->parent == baby_sitter);
+	krg_action_enable(task->parent, EPM_MIGRATE, 0);
+	krg_action_enable(task, EPM_MIGRATE, 0);
+}
+
+/* Assumes at least read_lock on tasklist */
+/* Called with write_lock_irq on tasklist */
+void krg_ptrace_reparent_ptraced(struct task_struct *real_parent,
+				 struct task_struct *task)
+{
+	/*
+	 * We do not support that the new real parent can migrate at
+	 * all. This will not induce new limitations as long as threads can not
+	 * migrate.
+	 */
+
+	/* Not really needed as long as zombies do not migrate... */
+	krg_action_enable(real_parent, EPM_MIGRATE, 0);
+	/* new real_parent has already been assigned. */
+	BUG_ON(task->real_parent == baby_sitter);
+	if (!is_container_init(task->real_parent)
+	    && task->real_parent != task->parent) {
+		int retval;
+
+		retval = krg_action_disable(task->real_parent, EPM_MIGRATE, 0);
+		BUG_ON(retval);
+	}
+}
 
+#endif /* CONFIG_KRG_EPM */
 
 /*
  * Initialize a new task whose father had been ptraced.
@@ -81,6 +163,9 @@ void __ptrace_unlink(struct task_struct *child)
 {
 	BUG_ON(!child->ptrace);
 
+#ifdef CONFIG_KRG_EPM
+	krg_ptrace_unlink(child);
+#endif
 	child->ptrace = 0;
 	child->parent = child->real_parent;
 	list_del_init(&child->ptrace_entry);
@@ -176,6 +261,10 @@ bool ptrace_may_access(struct task_struct *task, unsigned int mode)
 
 int ptrace_attach(struct task_struct *task)
 {
+#ifdef CONFIG_KRG_EPM
+	struct children_kddm_object *parent_children_obj;
+	pid_t real_parent_tgid;
+#endif
 	int retval;
 	unsigned long flags;
 
@@ -191,6 +280,13 @@ int ptrace_attach(struct task_struct *task)
 	retval = mutex_lock_interruptible(&task->cred_exec_mutex);
 	if (retval  < 0)
 		goto out;
+#ifdef CONFIG_KRG_EPM
+	down_read(&kerrighed_init_sem);
+	parent_children_obj = rcu_dereference(task->parent_children_obj);
+	if (parent_children_obj)
+		parent_children_obj =
+			krg_parent_children_writelock(task, &real_parent_tgid);
+#endif /* CONFIG_KRG_EPM */
 
 	retval = -EPERM;
 repeat:
@@ -220,6 +316,16 @@ repeat:
 	retval = __ptrace_may_access(task, PTRACE_MODE_ATTACH);
 	if (retval)
 		goto bad;
+#ifdef CONFIG_KRG_EPM
+	retval = krg_set_child_ptraced(parent_children_obj, task, 1);
+	if (retval)
+		goto bad;
+	retval = krg_ptrace_link(task, current);
+	if (retval) {
+		krg_set_child_ptraced(parent_children_obj, task, 0);
+		goto bad;
+	}
+#endif /* CONFIG_KRG_EPM */
 
 	/* Go */
 	task->ptrace |= PT_PTRACED;
@@ -232,6 +338,11 @@ repeat:
 bad:
 	write_unlock_irqrestore(&tasklist_lock, flags);
 	task_unlock(task);
+#ifdef CONFIG_KRG_EPM
+	if (parent_children_obj)
+		krg_children_unlock(parent_children_obj);
+	up_read(&kerrighed_init_sem);
+#endif /* CONFIG_KRG_EPM */
 	mutex_unlock(&task->cred_exec_mutex);
 out:
 	return retval;
@@ -287,6 +398,10 @@ static bool __ptrace_detach(struct task_struct *tracer, struct task_struct *p)
 
 int ptrace_detach(struct task_struct *child, unsigned int data)
 {
+#ifdef CONFIG_KRG_EPM
+	struct children_kddm_object *parent_children_obj;
+	pid_t real_parent_tgid;
+#endif
 	bool dead = false;
 
 	if (!valid_signal(data))
@@ -296,6 +411,13 @@ int ptrace_detach(struct task_struct *child, unsigned int data)
 	ptrace_disable(child);
 	clear_tsk_thread_flag(child, TIF_SYSCALL_TRACE);
 
+#ifdef CONFIG_KRG_EPM
+	down_read(&kerrighed_init_sem);
+	parent_children_obj = rcu_dereference(child->parent_children_obj);
+	if (parent_children_obj)
+		parent_children_obj =
+			krg_parent_children_writelock(child, &real_parent_tgid);
+#endif /* CONFIG_KRG_EPM */
 	write_lock_irq(&tasklist_lock);
 	/*
 	 * This child can be already killed. Make sure de_thread() or
@@ -304,13 +426,23 @@ int ptrace_detach(struct task_struct *child, unsigned int data)
 	if (child->ptrace) {
 		child->exit_code = data;
 		dead = __ptrace_detach(current, child);
+#ifdef CONFIG_KRG_EPM
+		krg_set_child_ptraced(parent_children_obj, child, 0);
+#endif
 		if (!child->exit_state)
 			wake_up_process(child);
 	}
 	write_unlock_irq(&tasklist_lock);
+#ifdef CONFIG_KRG_EPM
+	if (parent_children_obj)
+		krg_children_unlock(parent_children_obj);
+#endif /* CONFIG_KRG_EPM */
 
 	if (unlikely(dead))
 		release_task(child);
+#ifdef CONFIG_KRG_EPM
+	up_read(&kerrighed_init_sem);
+#endif
 
 	return 0;
 }
@@ -321,16 +453,35 @@ int ptrace_detach(struct task_struct *child, unsigned int data)
 void exit_ptrace(struct task_struct *tracer)
 {
 	struct task_struct *p, *n;
+#ifdef CONFIG_KRG_EPM
+	struct children_kddm_object *parent_children_obj;
+	LIST_HEAD(ptraced);
+	int dead;
+#endif
 	LIST_HEAD(ptrace_dead);
 
 	write_lock_irq(&tasklist_lock);
+#ifdef CONFIG_KRG_EPM
+	list_splice_init(&tracer->ptraced, &ptraced);
+#else /* !CONFIG_KRG_EPM */
 	list_for_each_entry_safe(p, n, &tracer->ptraced, ptrace_entry) {
 		if (__ptrace_detach(tracer, p))
 			list_add(&p->ptrace_entry, &ptrace_dead);
 	}
+#endif /* !CONFIG_KRG_EPM */
 	write_unlock_irq(&tasklist_lock);
 
 	BUG_ON(!list_empty(&tracer->ptraced));
+#ifdef CONFIG_KRG_EPM
+	list_for_each_entry_safe(p, n, &ptraced, ptrace_entry) {
+		parent_children_obj = krg_prepare_exit_ptrace_task(tracer, p);
+		dead = __ptrace_detach(tracer, p);
+		if (dead)
+			list_add(&p->ptrace_entry, &ptrace_dead);
+		krg_finish_exit_ptrace_task(p, parent_children_obj, dead);
+	}
+	BUG_ON(!list_empty(&ptraced));
+#endif /* CONFIG_KRG_EPM */
 
 	list_for_each_entry_safe(p, n, &ptrace_dead, ptrace_entry) {
 		list_del_init(&p->ptrace_entry);
@@ -583,8 +734,19 @@ int ptrace_request(struct task_struct *child, long request,
  */
 int ptrace_traceme(void)
 {
+#ifdef CONFIG_KRG_EPM
+	struct children_kddm_object *parent_children_obj;
+	pid_t real_parent_tgid;
+#endif /* CONFIG_KRG_EPM */
 	int ret = -EPERM;
 
+#ifdef CONFIG_KRG_EPM
+	down_read(&kerrighed_init_sem);
+	parent_children_obj = rcu_dereference(current->parent_children_obj);
+	if (parent_children_obj)
+		parent_children_obj =
+			krg_parent_children_writelock(current, &real_parent_tgid);
+#endif /* CONFIG_KRG_EPM */
 	/*
 	 * Are we already being traced?
 	 */
@@ -603,7 +765,23 @@ repeat:
 			goto repeat;
 		}
 
+#ifdef CONFIG_KRG_EPM
+		if (current->parent == baby_sitter)
+			ret = -EPERM;
+		else
+#endif
 		ret = security_ptrace_traceme(current->parent);
+#ifdef CONFIG_KRG_EPM
+		if (!ret)
+			ret = krg_set_child_ptraced(parent_children_obj,
+						    current, 1);
+		if (!ret) {
+			ret = krg_ptrace_link(current, current->parent);
+			if (ret)
+				krg_set_child_ptraced(parent_children_obj,
+						      current, 0);
+		}
+#endif /* CONFIG_KRG_EPM */
 
 		/*
 		 * Check PF_EXITING to ensure ->real_parent has not passed
@@ -614,10 +792,26 @@ repeat:
 			current->ptrace |= PT_PTRACED;
 			__ptrace_link(current, current->real_parent);
 		}
+#ifdef CONFIG_KRG_EPM
+		else if (!ret) {
+			/*
+			 * Since tracer should have been real_parent, it's ok
+			 * to call krg_ptrace_unlink() without having called
+			 * __ptrace_link() before.
+			 */
+			krg_ptrace_unlink(current);
+			krg_set_child_ptraced(parent_children_obj, current, 0);
+		}
+#endif /* CONFIG_KRG_EPM */
 
 		write_unlock_irqrestore(&tasklist_lock, flags);
 	}
 	task_unlock(current);
+#ifdef CONFIG_KRG_EPM
+	if (parent_children_obj)
+		krg_children_unlock(parent_children_obj);
+	up_read(&kerrighed_init_sem);
+#endif /* CONFIG_KRG_EPM */
 	return ret;
 }
 
diff --git a/kernel/sched.c b/kernel/sched.c
index 26efa47..c06ab81 100644
