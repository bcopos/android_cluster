--- a/kernel/cgroup.c
+++ b/kernel/cgroup.c
@@ -46,6 +46,10 @@
 #include <linux/cgroupstats.h>
 #include <linux/hash.h>
 #include <linux/namei.h>
+#ifdef CONFIG_KRG_EPM
+#include <kerrighed/ghost.h>
+#include <kerrighed/action.h>
+#endif
 
 #include <asm/atomic.h>
 
@@ -3606,3 +3610,39 @@ css_get_next(struct cgroup_subsys *ss, int id,
 	return ret;
 }
 
+#ifdef CONFIG_KRG_EPM
+int export_cgroups(struct epm_action *action,
+		   ghost_t *ghost, struct task_struct *task)
+{
+	int err = 0;
+
+	/* TODO */
+	if (task->cgroups != &init_css_set)
+		err = -EBUSY;
+
+	return err;
+}
+
+int import_cgroups(struct epm_action *action,
+		   ghost_t *ghost, struct task_struct *task)
+{
+	/* TODO */
+	get_css_set(&init_css_set);
+	task->cgroups = &init_css_set;
+	INIT_LIST_HEAD(&task->cg_list);
+
+	return 0;
+}
+
+void unimport_cgroups(struct task_struct *task)
+{
+	/* TODO */
+	cgroup_exit(task, 0);
+}
+
+void free_ghost_cgroups(struct task_struct *ghost)
+{
+	/* TODO */
+	cgroup_exit(ghost, 0);
+}
+#endif /* CONFIG_KRG_EPM */
diff --git a/kernel/compat.c b/kernel/compat.c
index 42d5654..05ca5f2 100644
