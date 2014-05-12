--- a/include/linux/magic.h
+++ b/include/linux/magic.h
@@ -50,4 +50,7 @@
 #define INOTIFYFS_SUPER_MAGIC	0x2BAD1DEA
 
 #define STACK_END_MAGIC		0x57AC6E9D
+#ifdef CONFIG_KRG_DVFS
+#define OCFS2_SUPER_MAGIC		0x7461636f
+#endif
 #endif /* __LINUX_MAGIC_H__ */
diff --git a/include/linux/memcontrol.h b/include/linux/memcontrol.h
index 25b9ca9..272c424 100644
