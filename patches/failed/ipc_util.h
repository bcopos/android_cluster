--- a/ipc/util.h
+++ b/ipc/util.h
@@ -11,6 +11,10 @@
 #define _IPC_UTIL_H
 
 #include <linux/err.h>
+#ifdef CONFIG_KRG_IPC
+#include <kerrighed/types.h>
+#include <kddm/kddm_types.h>
+#endif
 
 #define SEQ_MULTIPLIER	(IPCMNI)
 
@@ -46,6 +50,12 @@ static inline void msg_exit_ns(struct ipc_namespace *ns) { }
 static inline void shm_exit_ns(struct ipc_namespace *ns) { }
 #endif
 
+#ifdef CONFIG_KRG_IPC
+#define sem_ids(ns)     ((ns)->ids[IPC_SEM_IDS])
+#define msg_ids(ns)     ((ns)->ids[IPC_MSG_IDS])
+#define shm_ids(ns)     ((ns)->ids[IPC_SHM_IDS])
+#endif
+
 /*
  * Structure that holds the parameters needed by the ipc operations
  * (see after)
@@ -57,6 +67,9 @@ struct ipc_params {
 		size_t size;	/* for shared memories */
 		int nsems;	/* for semaphores */
 	} u;			/* holds the getnew() specific param */
+#ifdef CONFIG_KRG_IPC
+	int requested_id;
+#endif
 };
 
 /*
@@ -93,7 +106,11 @@ void __init ipc_init_proc_interface(const char *path, const char *header,
 #define ipcid_to_idx(id) ((id) % SEQ_MULTIPLIER)
 
 /* must be called with ids->rw_mutex acquired for writing */
+#ifdef CONFIG_KRG_IPC
+int ipc_addid(struct ipc_ids *, struct kern_ipc_perm *, int, int);
+#else
 int ipc_addid(struct ipc_ids *, struct kern_ipc_perm *, int);
+#endif
 
 /* must be called with ids->rw_mutex acquired for reading */
 int ipc_get_maxid(struct ipc_ids *);
@@ -121,6 +138,9 @@ void ipc_rcu_getref(void *ptr);
 void ipc_rcu_putref(void *ptr);
 
 struct kern_ipc_perm *ipc_lock(struct ipc_ids *, int);
+#ifdef CONFIG_KRG_IPC
+struct kern_ipc_perm *local_ipc_lock(struct ipc_ids *ids, int id);
+#endif
 
 void kernel_to_ipc64_perm(struct kern_ipc_perm *in, struct ipc64_perm *out);
 void ipc64_perm_to_ipc_perm(struct ipc64_perm *in, struct ipc_perm *out);
@@ -158,18 +178,58 @@ static inline int ipc_checkid(struct kern_ipc_perm *ipcp, int uid)
 
 static inline void ipc_lock_by_ptr(struct kern_ipc_perm *perm)
 {
+#ifdef CONFIG_KRG_IPC
+	BUG_ON(perm->krgops);
+#endif
 	rcu_read_lock();
+#ifdef CONFIG_KRG_IPC
+	mutex_lock(&perm->mutex);
+#else
 	spin_lock(&perm->lock);
+#endif
 }
 
+#ifdef CONFIG_KRG_IPC
+void ipc_unlock(struct kern_ipc_perm *perm);
+
+void local_ipc_unlock(struct kern_ipc_perm *perm);
+#else
 static inline void ipc_unlock(struct kern_ipc_perm *perm)
 {
 	spin_unlock(&perm->lock);
 	rcu_read_unlock();
 }
+#endif
 
 struct kern_ipc_perm *ipc_lock_check(struct ipc_ids *ids, int id);
 int ipcget(struct ipc_namespace *ns, struct ipc_ids *ids,
 			struct ipc_ops *ops, struct ipc_params *params);
 
+#ifdef CONFIG_KRG_IPC
+
+struct krgipc_ops {
+	struct kddm_set *map_kddm_set;
+	struct kddm_set *key_kddm_set;
+	struct kddm_set *data_kddm_set;
+
+	struct kern_ipc_perm *(*ipc_lock)(struct ipc_ids *, int);
+	void (*ipc_unlock)(struct kern_ipc_perm *);
+	struct kern_ipc_perm *(*ipc_findkey)(struct ipc_ids *, key_t);
+};
+
+int local_ipc_reserveid(struct ipc_ids* ids, struct kern_ipc_perm* new,
+                        int size);
+
+int is_krg_ipc(struct ipc_ids *ids);
+
+int krg_msg_init_ns(struct ipc_namespace *ns);
+int krg_sem_init_ns(struct ipc_namespace *ns);
+int krg_shm_init_ns(struct ipc_namespace *ns);
+
+void krg_msg_exit_ns(struct ipc_namespace *ns);
+void krg_sem_exit_ns(struct ipc_namespace *ns);
+void krg_shm_exit_ns(struct ipc_namespace *ns);
+
+#endif
+
 #endif
diff --git a/kddm/Makefile b/kddm/Makefile
new file mode 100644
index 0000000..18a0c50
