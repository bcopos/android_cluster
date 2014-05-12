--- a/fs/inode.c
+++ b/fs/inode.c
@@ -148,6 +148,9 @@ struct inode *inode_init_always(struct super_block *sb, struct inode *inode)
 	inode->i_cdev = NULL;
 	inode->i_rdev = 0;
 	inode->dirtied_when = 0;
+#ifdef CONFIG_KRG_DVFS
+	inode->i_objid = 0;
+#endif
 
 	if (security_inode_alloc(inode))
 		goto out_free_inode;
@@ -165,6 +168,9 @@ struct inode *inode_init_always(struct super_block *sb, struct inode *inode)
 	init_rwsem(&inode->i_alloc_sem);
 	lockdep_set_class(&inode->i_alloc_sem, &sb->s_type->i_alloc_sem_key);
 
+#ifdef CONFIG_KRG_DVFS
+	mapping->kddm_set = NULL;
+#endif
 	mapping->a_ops = &empty_aops;
 	mapping->host = inode;
 	mapping->flags = 0;
diff --git a/fs/ioctl.c b/fs/ioctl.c
index 82d9c42..fccad59 100644
