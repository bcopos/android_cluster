--- a/arch/x86/include/asm/thread_info.h
+++ b/arch/x86/include/asm/thread_info.h
@@ -95,6 +95,12 @@ struct thread_info {
 #define TIF_DEBUGCTLMSR		25	/* uses thread_struct.debugctlmsr */
 #define TIF_DS_AREA_MSR		26      /* uses thread_struct.ds_area_msr */
 #define TIF_SYSCALL_FTRACE	27	/* for ftrace syscall instrumentation */
+#ifdef CONFIG_KRG_FAF
+#define TIF_RUACCESS            28
+#endif
+#ifdef CONFIG_KRG_EPM
+#define TIF_MIGRATION		29
+#endif
 
 #define _TIF_SYSCALL_TRACE	(1 << TIF_SYSCALL_TRACE)
 #define _TIF_NOTIFY_RESUME	(1 << TIF_NOTIFY_RESUME)
@@ -117,6 +123,12 @@ struct thread_info {
 #define _TIF_DEBUGCTLMSR	(1 << TIF_DEBUGCTLMSR)
 #define _TIF_DS_AREA_MSR	(1 << TIF_DS_AREA_MSR)
 #define _TIF_SYSCALL_FTRACE	(1 << TIF_SYSCALL_FTRACE)
+#ifdef CONFIG_KRG_FAF
+#define _TIF_RUACCESS           (1 << TIF_RUACCESS)
+#endif
+#ifdef CONFIG_KRG_EPM
+#define _TIF_MIGRATION		(1 << TIF_MIGRATION)
+#endif
 
 /* work to do in syscall_trace_enter() */
 #define _TIF_WORK_SYSCALL_ENTRY	\
diff --git a/arch/x86/include/asm/uaccess.h b/arch/x86/include/asm/uaccess.h
index b685ece..5ba660e 100644
