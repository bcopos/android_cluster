--- a/fs/nfs/inode.c
+++ b/fs/nfs/inode.c
@@ -37,6 +37,9 @@
 #include <linux/vfs.h>
 #include <linux/inet.h>
 #include <linux/nfs_xdr.h>
+#ifdef CONFIG_KRG_MM
+#include <kerrighed/krgsyms.h>
+#endif
 
 #include <asm/system.h>
 #include <asm/uaccess.h>
@@ -1443,6 +1446,12 @@ static int __init init_nfs_fs(void)
 {
 	int err;
 
+#ifdef CONFIG_KRG_MM
+	err = krgsyms_register(KRGSYMS_VM_OPS_NFS_FILE, &nfs_file_vm_ops);
+	if (err)
+		goto out8;
+#endif
+
 	err = nfs_fscache_register();
 	if (err < 0)
 		goto out7;
@@ -1501,6 +1510,10 @@ out5:
 out6:
 	nfs_fscache_unregister();
 out7:
+#ifdef CONFIG_KRG_MM
+	krgsyms_unregister(KRGSYMS_VM_OPS_NFS_FILE);
+out8:
+#endif
 	return err;
 }
 
@@ -1518,6 +1531,9 @@ static void __exit exit_nfs_fs(void)
 	unregister_nfs_fs();
 	nfs_fs_proc_exit();
 	nfsiod_stop();
+#ifdef CONFIG_KRG_MM
+	krgsyms_unregister(KRGSYMS_VM_OPS_NFS_FILE);
+#endif
 }
 
 /* Not quite true; I just maintain it */
diff --git a/fs/nfs/internal.h b/fs/nfs/internal.h
index e4d6a83..988669b 100644
