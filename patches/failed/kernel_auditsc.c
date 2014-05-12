--- a/kernel/auditsc.c
+++ b/kernel/auditsc.c
@@ -67,6 +67,10 @@
 #include <linux/inotify.h>
 #include <linux/capability.h>
 #include <linux/fs_struct.h>
+#ifdef CONFIG_KRG_EPM
+#include <kerrighed/action.h>
+#include <kerrighed/ghost.h>
+#endif
 
 #include "audit.h"
 
@@ -1665,6 +1669,75 @@ void audit_finish_fork(struct task_struct *child)
 	p->current_state = ctx->current_state;
 }
 
+#ifdef CONFIG_KRG_EPM
+int export_audit_context(struct epm_action *action,
+			 ghost_t *ghost, struct task_struct *task)
+{
+	struct audit_context *ctx = task->audit_context;
+	int err = 0;
+
+	if (ctx)
+		err = ghost_write(ghost, ctx, sizeof(*ctx));
+
+	return err;
+}
+
+int import_audit_context(struct epm_action *action,
+			 ghost_t *ghost, struct task_struct *task)
+{
+	struct audit_context ctx;
+	struct audit_context *p;
+	int err = 0;
+
+	if (!task->audit_context)
+		goto out;
+
+	err = ghost_read(ghost, &ctx, sizeof(ctx));
+	if (err)
+		goto out;
+
+	task->audit_context = NULL;
+	err = audit_alloc(task);
+	if (err)
+		goto out;
+
+	p = task->audit_context;
+	if (!p)
+		goto out;
+
+	p->arch = ctx.arch;
+	p->major = ctx.major;
+	memcpy(p->argv, ctx.argv, sizeof(ctx.argv));
+	p->ctime = ctx.ctime;
+	p->dummy = ctx.dummy;
+	p->in_syscall = ctx.in_syscall;
+	/* Keep filterkey as assigned by audit_alloc() */
+	/* Keep RPC handler's pid as ppid */
+	p->ppid = current->pid;
+	p->prio = ctx.prio;
+	p->current_state = ctx.current_state;
+
+out:
+	return err;
+}
+
+void unimport_audit_context(struct task_struct *task)
+{
+	struct audit_context *ctx = task->audit_context;
+
+	if (ctx)
+		audit_free_context(ctx);
+}
+
+void free_ghost_audit_context(struct task_struct *task)
+{
+	struct audit_context *ctx = task->audit_context;
+
+	if (ctx)
+		audit_free_context(ctx);
+}
+#endif /* CONFIG_KRG_EPM */
+
 /**
  * audit_syscall_exit - deallocate audit context after a system call
  * @valid: success/failure flag
diff --git a/kernel/cgroup.c b/kernel/cgroup.c
index a7267bf..0c3e361 100644
