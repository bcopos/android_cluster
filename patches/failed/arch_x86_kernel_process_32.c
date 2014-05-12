--- a/arch/x86/kernel/process_32.c
+++ b/arch/x86/kernel/process_32.c
@@ -255,6 +255,10 @@ int copy_thread(unsigned long clone_flags, unsigned long sp,
 
 	childregs = task_pt_regs(p);
 	*childregs = *regs;
+#ifdef CONFIG_KRG_EPM
+	/* Do not corrupt ax in migration/restart */
+	if (!krg_current || in_krg_do_fork())
+#endif
 	childregs->ax = 0;
 	childregs->sp = sp;
 
@@ -263,6 +267,9 @@ int copy_thread(unsigned long clone_flags, unsigned long sp,
 
 	p->thread.ip = (unsigned long) ret_from_fork;
 
+#ifdef CONFIG_KRG_EPM
+	if (!krg_current)
+#endif
 	task_user_gs(p) = get_user_gs(regs);
 
 	tsk = current;
@@ -292,8 +299,15 @@ int copy_thread(unsigned long clone_flags, unsigned long sp,
 
 	ds_copy_thread(p, current);
 
+#ifdef CONFIG_KRG_EPM
+	/* Do not corrupt debugctlmsr in migration/restart */
+	if (!krg_current || in_krg_do_fork()) {
+#endif
 	clear_tsk_thread_flag(p, TIF_DEBUGCTLMSR);
 	p->thread.debugctlmsr = 0;
+#ifdef CONFIG_KRG_EPM
+	}
+#endif
 
 	return err;
 }
diff --git a/arch/x86/kernel/process_64.c b/arch/x86/kernel/process_64.c
index b751a41..18313de 100644
