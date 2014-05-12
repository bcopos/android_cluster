--- a/fs/exec.c
+++ b/fs/exec.c
@@ -54,6 +54,16 @@
 #include <linux/kmod.h>
 #include <linux/fsnotify.h>
 #include <linux/fs_struct.h>
+#ifdef CONFIG_KRG_CAP
+#include <kerrighed/capabilities.h>
+#endif
+#ifdef CONFIG_KRG_PROC
+#include <kerrighed/task.h>
+#include <kerrighed/krginit.h>
+#endif
+#ifdef CONFIG_KRG_EPM
+#include <kerrighed/signal.h>
+#endif
 
 #include <asm/uaccess.h>
 #include <asm/mmu_context.h>
@@ -627,6 +637,11 @@ int setup_arg_pages(struct linux_binprm *bprm,
 		}
 	}
 
+#ifdef CONFIG_KRG_MM
+	if (mm->anon_vma_kddm_set)
+		krg_check_vma_link(vma);
+#endif
+
 #ifdef CONFIG_STACK_GROWSUP
 	stack_base = vma->vm_end + EXTRA_STACK_VM_PAGES * PAGE_SIZE;
 #else
@@ -698,6 +713,9 @@ static int exec_mmap(struct mm_struct *mm)
 {
 	struct task_struct *tsk;
 	struct mm_struct * old_mm, *active_mm;
+#ifdef CONFIG_KRG_MM
+	unique_id_t mm_id = 0;
+#endif
 
 	/* Notify parent that we're no longer interested in the old VM */
 	tsk = current;
@@ -711,6 +729,9 @@ static int exec_mmap(struct mm_struct *mm)
 		 * through with the exec.  We must hold mmap_sem around
 		 * checking core_state and changing tsk->mm.
 		 */
+#ifdef CONFIG_KRG_MM
+		mm_id = old_mm->mm_id;
+#endif
 		down_read(&old_mm->mmap_sem);
 		if (unlikely(old_mm->core_state)) {
 			up_read(&old_mm->mmap_sem);
@@ -729,6 +750,10 @@ static int exec_mmap(struct mm_struct *mm)
 		BUG_ON(active_mm != old_mm);
 		mm_update_next_owner(old_mm);
 		mmput(old_mm);
+#ifdef CONFIG_KRG_MM
+		if (mm_id)
+			kh_mm_release(old_mm, 1);
+#endif
 		return 0;
 	}
 	mmdrop(active_mm);
@@ -784,7 +809,16 @@ static int de_thread(struct task_struct *tsk)
 	 */
 	if (!thread_group_leader(tsk)) {
 		struct task_struct *leader = tsk->group_leader;
+#ifdef CONFIG_KRG_PROC
+		struct task_kddm_object *obj;
+#endif
+#ifdef CONFIG_KRG_EPM
+		struct children_kddm_object *parent_children_obj;
+#endif
 
+#ifdef CONFIG_KRG_PROC
+		down_read(&kerrighed_init_sem);
+#endif
 		sig->notify_count = -1;	/* for exit_notify() */
 		for (;;) {
 			write_lock_irq(&tasklist_lock);
@@ -795,6 +829,33 @@ static int de_thread(struct task_struct *tsk)
 			schedule();
 		}
 
+#ifdef CONFIG_KRG_EPM
+		parent_children_obj = rcu_dereference(tsk->parent_children_obj);
+#endif
+#ifdef CONFIG_KRG_PROC
+		/* tsk's pid will disappear just below. */
+		obj = leader->task_obj;
+		BUG_ON(!obj ^ !tsk->task_obj);
+		if (
+		    obj
+#ifdef CONFIG_KRG_EPM
+		    || parent_children_obj
+#endif
+		   ) {
+			write_unlock_irq(&tasklist_lock);
+
+#ifdef CONFIG_KRG_EPM
+			parent_children_obj =
+				krg_children_prepare_de_thread(tsk);
+#endif
+			krg_task_free(tsk);
+
+			if (obj)
+				__krg_task_writelock(leader);
+
+			write_lock_irq(&tasklist_lock);
+		}
+#endif /* CONFIG_KRG_PROC */
 		/*
 		 * The only record we have of the real-time age of a
 		 * process, regardless of execs it's done, is start_time.
@@ -827,6 +888,12 @@ static int de_thread(struct task_struct *tsk)
 		transfer_pid(leader, tsk, PIDTYPE_PGID);
 		transfer_pid(leader, tsk, PIDTYPE_SID);
 		list_replace_rcu(&leader->tasks, &tsk->tasks);
+#ifdef CONFIG_KRG_PROC
+		rcu_assign_pointer(leader->task_obj, NULL);
+		if (obj)
+			rcu_assign_pointer(obj->task, tsk);
+		rcu_assign_pointer(tsk->task_obj, obj);
+#endif
 
 		tsk->group_leader = tsk;
 		leader->group_leader = tsk;
@@ -836,8 +903,19 @@ static int de_thread(struct task_struct *tsk)
 		BUG_ON(leader->exit_state != EXIT_ZOMBIE);
 		leader->exit_state = EXIT_DEAD;
 		write_unlock_irq(&tasklist_lock);
+#ifdef CONFIG_KRG_PROC
+		/* tsk has taken leader's pid. */
+		if (obj)
+			__krg_task_unlock(tsk);
+#endif /* CONFIG_KRG_PROC */
+#ifdef CONFIG_KRG_EPM
+		krg_children_finish_de_thread(parent_children_obj, tsk);
+#endif
 
 		release_task(leader);
+#ifdef CONFIG_KRG_PROC
+		up_read(&kerrighed_init_sem);
+#endif
 	}
 
 	sig->group_exit_task = NULL;
@@ -860,6 +938,11 @@ no_thread_group:
 		atomic_set(&newsighand->count, 1);
 		memcpy(newsighand->action, oldsighand->action,
 		       sizeof(newsighand->action));
+#ifdef CONFIG_KRG_EPM
+		down_read(&kerrighed_init_sem);
+
+		krg_sighand_alloc_unshared(tsk, newsighand);
+#endif
 
 		write_lock_irq(&tasklist_lock);
 		spin_lock(&oldsighand->siglock);
@@ -867,7 +950,13 @@ no_thread_group:
 		spin_unlock(&oldsighand->siglock);
 		write_unlock_irq(&tasklist_lock);
 
+#ifdef CONFIG_KRG_EPM
+		krg_sighand_cleanup(oldsighand);
+
+		up_read(&kerrighed_init_sem);
+#else
 		__cleanup_sighand(oldsighand);
+#endif
 	}
 
 	BUG_ON(!thread_group_leader(tsk));
@@ -994,6 +1083,9 @@ int flush_old_exec(struct linux_binprm * bprm)
 	   group */
 
 	current->self_exec_id++;
+#ifdef CONFIG_KRG_EPM
+	krg_update_self_exec_id(current);
+#endif
 			
 	flush_signal_handlers(current, 0);
 	flush_old_files(current->files);
@@ -1105,6 +1197,12 @@ int prepare_binprm(struct linux_binprm *bprm)
 		return retval;
 	bprm->cred_prepared = 1;
 
+#ifdef CONFIG_KRG_CAP
+	retval = krg_cap_prepare_binprm(bprm);
+	if (retval)
+		return retval;
+#endif
+
 	memset(bprm->buf, 0, BINPRM_BUF_SIZE);
 	return kernel_read(bprm->file, 0, bprm->buf, BINPRM_BUF_SIZE);
 }
@@ -1328,10 +1426,18 @@ int do_execve(char * filename,
 	if (retval < 0)
 		goto out;
 
+#ifdef CONFIG_KRG_MM
+	retval = krg_do_execve(current, current->mm);
+	if (retval)
+		goto out;
+#endif
 	/* execve succeeded */
 	current->fs->in_exec = 0;
 	current->in_execve = 0;
 	mutex_unlock(&current->cred_exec_mutex);
+#ifdef CONFIG_KRG_CAP
+	krg_cap_finish_exec(bprm);
+#endif
 	acct_update_integrals(current);
 	free_bprm(bprm);
 	if (displaced)
@@ -1339,6 +1445,11 @@ int do_execve(char * filename,
 	return retval;
 
 out:
+#ifdef CONFIG_KRG_EPM
+	/* Quiet the BUG_ON() in mmput() */
+	if (bprm->mm)
+		atomic_dec(&bprm->mm->mm_ltasks);
+#endif
 	if (bprm->mm)
 		mmput (bprm->mm);
 
@@ -1622,6 +1733,11 @@ static int coredump_wait(int exit_code, struct core_state *core_state)
 	vfork_done = tsk->vfork_done;
 	if (vfork_done) {
 		tsk->vfork_done = NULL;
+#ifdef CONFIG_KRG_EPM
+		if (tsk->remote_vfork_done)
+			krg_vfork_done(vfork_done);
+		else
+#endif
 		complete(vfork_done);
 	}
 
diff --git a/fs/fcntl.c b/fs/fcntl.c
index 1ad7031..99b155c 100644
