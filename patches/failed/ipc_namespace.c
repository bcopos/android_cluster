--- a/ipc/namespace.c
+++ b/ipc/namespace.c
@@ -14,6 +14,38 @@
 
 #include "util.h"
 
+#ifdef CONFIG_KRG_IPC
+static int krg_init_ipc_ns(struct ipc_namespace *ns)
+{
+	int err = 0;
+
+	if (!current->create_krg_ns)
+		goto exit;
+
+	err = krg_sem_init_ns(ns);
+	if (err)
+		goto err_sem;
+
+	err = krg_msg_init_ns(ns);
+	if (err)
+		goto err_msg;
+
+	err = krg_shm_init_ns(ns);
+	if (err)
+		goto err_shm;
+
+	return err;
+
+err_shm:
+	krg_msg_exit_ns(ns);
+err_msg:
+	krg_sem_exit_ns(ns);
+err_sem:
+exit:
+	return err;
+}
+#endif
+
 static struct ipc_namespace *clone_ipc_ns(struct ipc_namespace *old_ns)
 {
 	struct ipc_namespace *ns;
@@ -29,12 +61,21 @@ static struct ipc_namespace *clone_ipc_ns(struct ipc_namespace *old_ns)
 		kfree(ns);
 		return ERR_PTR(err);
 	}
-	atomic_inc(&nr_ipc_ns);
 
 	sem_init_ns(ns);
 	msg_init_ns(ns);
 	shm_init_ns(ns);
 
+#ifdef CONFIG_KRG_IPC
+	err = krg_init_ipc_ns(ns);
+	if (err) {
+		kfree(ns);
+		return ERR_PTR(err);
+	}
+#endif
+
+	atomic_inc(&nr_ipc_ns);
+
 	/*
 	 * msgmni has already been computed for the new ipc ns.
 	 * Thus, do the ipcns creation notification before registering that
@@ -132,6 +173,11 @@ void free_ipc_ns(struct ipc_namespace *ns)
 	sem_exit_ns(ns);
 	msg_exit_ns(ns);
 	shm_exit_ns(ns);
+#ifdef CONFIG_KRG_IPC
+	krg_sem_exit_ns(ns);
+	krg_msg_exit_ns(ns);
+	krg_shm_exit_ns(ns);
+#endif
 	kfree(ns);
 	atomic_dec(&nr_ipc_ns);
 
diff --git a/ipc/sem.c b/ipc/sem.c
index 16a2189..721b7ef 100644
