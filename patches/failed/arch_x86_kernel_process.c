--- a/arch/x86/kernel/process.c
+++ b/arch/x86/kernel/process.c
@@ -243,6 +243,18 @@ int sys_fork(struct pt_regs *regs)
  */
 int sys_vfork(struct pt_regs *regs)
 {
+#ifdef CONFIG_KRG_EPM
+#ifdef CONFIG_KRG_CAP
+	if (can_use_krg_cap(current, CAP_DISTANT_FORK))
+#endif
+	{
+		int retval = krg_do_fork(CLONE_VFORK | SIGCHLD,
+					 regs->sp, regs, 0,
+					 NULL, NULL, 0);
+		if (retval > 0)
+			return retval;
+	}
+#endif /* CONFIG_KRG_EPM */
 	return do_fork(CLONE_VFORK | CLONE_VM | SIGCHLD, regs->sp, regs, 0,
 		       NULL, NULL);
 }
diff --git a/arch/x86/kernel/process_32.c b/arch/x86/kernel/process_32.c
index 76f8f84..7133fdd 100644
