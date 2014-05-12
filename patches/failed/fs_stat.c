--- a/fs/stat.c
+++ b/fs/stat.c
@@ -14,6 +14,9 @@
 #include <linux/security.h>
 #include <linux/syscalls.h>
 #include <linux/pagemap.h>
+#ifdef CONFIG_KRG_FAF
+#include <kerrighed/faf.h>
+#endif
 
 #include <asm/uaccess.h>
 #include <asm/unistd.h>
@@ -61,6 +64,13 @@ int vfs_fstat(unsigned int fd, struct kstat *stat)
 	int error = -EBADF;
 
 	if (f) {
+#ifdef CONFIG_KRG_FAF
+		if (f->f_flags & O_FAF_CLT) {
+			error = krg_faf_fstat(f, stat);
+			fput(f);
+			return error;
+		}
+#endif
 		error = vfs_getattr(f->f_path.mnt, f->f_path.dentry, stat);
 		fput(f);
 	}
@@ -84,6 +94,15 @@ int vfs_fstatat(int dfd, char __user *filename, struct kstat *stat, int flag)
 	if (error)
 		goto out;
 
+#ifdef CONFIG_KRG_FAF
+	if ((!path.dentry) && (path.mnt)) {
+		struct file *file = (struct file *)path.mnt;
+		get_file (file);
+		error = krg_faf_fstat(file, stat);
+		fput(file);
+		return error;
+	}
+#endif
 	error = vfs_getattr(path.mnt, path.dentry, stat);
 	path_put(&path);
 out:
diff --git a/fs/sync.c b/fs/sync.c
index 7abc65f..d1a0bf8 100644
