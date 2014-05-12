--- a/include/linux/init_task.h
+++ b/include/linux/init_task.h
@@ -11,14 +11,33 @@
 #include <linux/user_namespace.h>
 #include <linux/securebits.h>
 #include <net/net_namespace.h>
+#ifdef CONFIG_KRG_CAP
+#include <kerrighed/capabilities.h>
+#endif
 
 extern struct files_struct init_files;
 extern struct fs_struct init_fs;
 
+#ifdef CONFIG_KRG_EPM
+#define INIT_MM_EPM						\
+	.mm_ltasks      = ATOMIC_INIT(1),
+#else
+#define INIT_MM_EPM
+#endif
+
+#ifdef CONFIG_KRG_MM
+#define INIT_MM_MM                                              \
+        .mm_tasks       = ATOMIC_INIT(1),
+#else
+#define INIT_MM_MM
+#endif
+
 #define INIT_MM(name) \
 {			 					\
 	.mm_rb		= RB_ROOT,				\
 	.pgd		= swapper_pg_dir, 			\
+	INIT_MM_MM						\
+	INIT_MM_EPM						\
 	.mm_users	= ATOMIC_INIT(2), 			\
 	.mm_count	= ATOMIC_INIT(1), 			\
 	.mmap_sem	= __RWSEM_INITIALIZER(name.mmap_sem),	\
@@ -108,6 +127,23 @@ extern struct group_info init_groups;
 
 extern struct cred init_cred;
 
+#ifdef CONFIG_KRG_CAP
+#define INIT_KRG_CAP .krg_caps = {			    \
+	.permitted = KRG_CAP_INIT_PERM_SET,		    \
+	.effective = KRG_CAP_INIT_EFF_SET,		    \
+	.inheritable_permitted = KRG_CAP_INIT_INH_PERM_SET, \
+	.inheritable_effective = KRG_CAP_INIT_INH_EFF_SET   \
+},
+#else
+#define INIT_KRG_CAP
+#endif
+
+#ifdef CONFIG_KRG_KDDM
+#define INIT_KDDM .kddm_info = NULL,
+#else
+#define INIT_KDDM
+#endif
+
 /*
  *  INIT_TASK is used to set up the first task table, touch at
  * your own risk!. Base=0, limit=0x1fffff (=2MB)
@@ -174,6 +210,8 @@ extern struct cred init_cred;
 	INIT_TRACE_IRQFLAGS						\
 	INIT_LOCKDEP							\
 	INIT_FTRACE_GRAPH						\
+	INIT_KRG_CAP							\
+	INIT_KDDM							\
 }
 
 
diff --git a/include/linux/ipc.h b/include/linux/ipc.h
index b882610..06cfe29 100644
