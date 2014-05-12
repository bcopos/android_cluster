--- a/include/linux/tracehook.h
+++ b/include/linux/tracehook.h
@@ -501,6 +501,11 @@ static inline int tracehook_notify_jctl(int notify, int why)
 static inline int tracehook_notify_death(struct task_struct *task,
 					 void **death_cookie, int group_dead)
 {
+#ifdef CONFIG_KRG_EPM
+	/* Remote ptracers are not supported yet. */
+	BUG_ON(task->ptrace && (task->parent == baby_sitter
+				|| task->real_parent == baby_sitter));
+#endif
 	if (task_detached(task))
 		return task->ptrace ? SIGCHLD : DEATH_REAP;
 
diff --git a/include/linux/unique_id.h b/include/linux/unique_id.h
new file mode 100644
index 0000000..bf340c1
