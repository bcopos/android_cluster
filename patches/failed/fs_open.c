--- a/fs/open.c
+++ b/fs/open.c
@@ -30,6 +30,9 @@
 #include <linux/audit.h>
 #include <linux/falloc.h>
 #include <linux/fs_struct.h>
+#ifdef CONFIG_KRG_IPC
+#include <kerrighed/faf.h>
+#endif
 
 int vfs_statfs(struct dentry *dentry, struct kstatfs *buf)
 {
@@ -167,7 +170,14 @@ SYSCALL_DEFINE2(fstatfs, unsigned int, fd, struct statfs __user *, buf)
 	file = fget(fd);
 	if (!file)
 		goto out;
+
+#ifdef CONFIG_KRG_FAF
+	if (file->f_flags & O_FAF_CLT)
+		error = krg_faf_fstatfs(file, &tmp);
+	else
+#endif
 	error = vfs_statfs_native(file->f_path.dentry, &tmp);
+
 	if (!error && copy_to_user(buf, &tmp, sizeof(tmp)))
 		error = -EFAULT;
 	fput(file);
@@ -981,7 +991,10 @@ struct file *dentry_open(struct dentry *dentry, struct vfsmount *mnt, int flags,
 }
 EXPORT_SYMBOL(dentry_open);
 
-static void __put_unused_fd(struct files_struct *files, unsigned int fd)
+#ifndef CONFIG_KRG_FAF
+static
+#endif
+void __put_unused_fd(struct files_struct *files, unsigned int fd)
 {
 	struct fdtable *fdt = files_fdtable(files);
 	__FD_CLR(fd, fdt->open_fds);
@@ -1011,6 +1024,16 @@ EXPORT_SYMBOL(put_unused_fd);
  * It should never happen - if we allow dup2() do it, _really_ bad things
  * will follow.
  */
+#ifdef CONFIG_KRG_FAF
+void __fd_install(struct files_struct *files,
+		  unsigned int fd, struct file *file)
+{
+	struct fdtable *fdt;
+	fdt = files_fdtable(files);
+	BUG_ON(fdt->fd[fd] != NULL);
+	rcu_assign_pointer(fdt->fd[fd], file);
+}
+#endif
 
 void fd_install(unsigned int fd, struct file *file)
 {
@@ -1030,6 +1053,12 @@ long do_sys_open(int dfd, const char __user *filename, int flags, int mode)
 	char *tmp = getname(filename);
 	int fd = PTR_ERR(tmp);
 
+#ifdef CONFIG_KRG_FAF
+       /* Flush Kerrighed O_flags to prevent kernel crashes due to wrong
+        * flags passed from userland.
+        */
+	flags = flags & (~O_KRG_FLAGS);
+#endif
 	if (!IS_ERR(tmp)) {
 		fd = get_unused_fd_flags(flags);
 		if (fd >= 0) {
@@ -1038,6 +1067,9 @@ long do_sys_open(int dfd, const char __user *filename, int flags, int mode)
 				put_unused_fd(fd);
 				fd = PTR_ERR(f);
 			} else {
+#ifdef CONFIG_KRG_FAF
+				if (!(f->f_flags & O_FAF_CLT))
+#endif
 				fsnotify_open(f->f_path.dentry);
 				fd_install(fd, f);
 			}
@@ -1094,6 +1126,9 @@ SYSCALL_DEFINE2(creat, const char __user *, pathname, int, mode)
 int filp_close(struct file *filp, fl_owner_t id)
 {
 	int retval = 0;
+#ifdef CONFIG_KRG_FAF
+	int flags = filp->f_flags;
+#endif
 
 	if (!file_count(filp)) {
 		printk(KERN_ERR "VFS: Close: file count is 0\n");
@@ -1103,9 +1138,19 @@ int filp_close(struct file *filp, fl_owner_t id)
 	if (filp->f_op && filp->f_op->flush)
 		retval = filp->f_op->flush(filp, id);
 
+#ifdef CONFIG_KRG_FAF
+	if (filp->f_flags & O_FAF_CLT) {
+		fput(filp);
+		return retval;
+	}
+#endif
 	dnotify_flush(filp, id);
 	locks_remove_posix(filp, id);
 	fput(filp);
+#ifdef CONFIG_KRG_FAF
+	if ((flags & O_FAF_SRV) && (file_count(filp) == 1))
+		krg_faf_srv_close(filp);
+#endif
 	return retval;
 }
 
diff --git a/fs/pipe.c b/fs/pipe.c
index 13414ec..3f6cbcd 100644
