--- a/include/linux/ipc_namespace.h
+++ b/include/linux/ipc_namespace.h
@@ -15,6 +15,9 @@
 
 #define IPCNS_CALLBACK_PRI 0
 
+#ifdef CONFIG_KRG_IPC
+struct krgipc_ops;
+#endif
 
 struct ipc_ids {
 	int in_use;
@@ -22,6 +25,9 @@ struct ipc_ids {
 	unsigned short seq_max;
 	struct rw_semaphore rw_mutex;
 	struct idr ipcs_idr;
+#ifdef CONFIG_KRG_IPC
+	struct krgipc_ops *krgops;
+#endif
 };
 
 struct ipc_namespace {
@@ -55,7 +61,6 @@ struct ipc_namespace {
 	unsigned int    mq_queues_max;   /* initialized to DFLT_QUEUESMAX */
 	unsigned int    mq_msg_max;      /* initialized to DFLT_MSGMAX */
 	unsigned int    mq_msgsize_max;  /* initialized to DFLT_MSGSIZEMAX */
-
 };
 
 extern struct ipc_namespace init_ipc_ns;
diff --git a/include/linux/kernel.h b/include/linux/kernel.h
index 883cd44..723f8eb 100644
