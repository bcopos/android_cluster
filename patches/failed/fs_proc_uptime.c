--- a/fs/proc/uptime.c
+++ b/fs/proc/uptime.c
@@ -6,7 +6,10 @@
 #include <linux/time.h>
 #include <asm/cputime.h>
 
-static int uptime_proc_show(struct seq_file *m, void *v)
+#ifndef CONFIG_KRG_PROCFS
+static
+#endif
+int uptime_proc_show(struct seq_file *m, void *v)
 {
 	struct timespec uptime;
 	struct timespec idle;
diff --git a/fs/read_write.c b/fs/read_write.c
index 9d1e76b..336bc8f 100644
