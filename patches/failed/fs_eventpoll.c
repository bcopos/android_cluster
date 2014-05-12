--- a/fs/eventpoll.c
+++ b/fs/eventpoll.c
@@ -33,6 +33,9 @@
 #include <linux/bitops.h>
 #include <linux/mutex.h>
 #include <linux/anon_inodes.h>
+#ifdef CONFIG_KRG_FAF
+#include <kerrighed/faf.h>
+#endif
 #include <asm/uaccess.h>
 #include <asm/system.h>
 #include <asm/io.h>
@@ -428,6 +431,10 @@ static void ep_unregister_pollwait(struct eventpoll *ep, struct epitem *epi)
 		list_del(&pwq->llink);
 		remove_wait_queue(pwq->whead, &pwq->wait);
 		kmem_cache_free(pwq_cache, pwq);
+#ifdef CONFIG_KRG_FAF
+		if (epi->ffd.file->f_flags & O_FAF_CLT)
+			krg_faf_poll_dequeue(epi->ffd.file);
+#endif
 	}
 }
 
@@ -865,9 +872,29 @@ static void ep_ptable_queue_proc(struct file *file, wait_queue_head_t *whead,
 		list_add_tail(&pwq->llink, &epi->pwqlist);
 		epi->nwait++;
 	} else {
+#ifdef CONFIG_KRG_FAF
+		pwq = NULL;
+#endif
 		/* We have to signal that an error occurred */
 		epi->nwait = -1;
 	}
+#ifdef CONFIG_KRG_FAF
+	if (file->f_flags & O_FAF_CLT) {
+		if (krg_faf_poll_wait(file, pwq != NULL)) {
+			if (pwq) {
+				/*
+				 * Don't let ep_unregister_pollwait() do the
+				 * cleanup, since it would call
+				 * krg_faf_poll_dequeue().
+				 */
+				list_del(&pwq->llink);
+				remove_wait_queue(whead, &pwq->wait);
+				kmem_cache_free(pwq_cache, pwq);
+				epi->nwait = -1;
+			}
+		}
+	}
+#endif
 }
 
 static void ep_rbtree_insert(struct eventpoll *ep, struct epitem *epi)
diff --git a/fs/exec.c b/fs/exec.c
index 895823d..562fc91 100644
