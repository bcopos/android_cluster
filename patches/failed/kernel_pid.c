--- a/kernel/pid.c
+++ b/kernel/pid.c
@@ -36,6 +36,10 @@
 #include <linux/pid_namespace.h>
 #include <linux/init_task.h>
 #include <linux/syscalls.h>
+#ifdef CONFIG_KRG_PROC
+#include <kerrighed/pid.h>
+#include <kerrighed/krginit.h>
+#endif
 
 #define pid_hashfn(nr, ns)	\
 	hash_long((unsigned long)nr + (unsigned long)ns, pidhash_shift)
@@ -78,6 +82,10 @@ struct pid_namespace init_pid_ns = {
 	.last_pid = 0,
 	.level = 0,
 	.child_reaper = &init_task,
+#ifdef CONFIG_KRG_PROC
+	.krg_ns_root = NULL,
+	.global = 0,
+#endif
 };
 EXPORT_SYMBOL_GPL(init_pid_ns);
 
@@ -112,9 +120,17 @@ EXPORT_SYMBOL(is_container_init);
 
 static  __cacheline_aligned_in_smp DEFINE_SPINLOCK(pidmap_lock);
 
+#ifdef CONFIG_KRG_EPM
+void __free_pidmap(struct upid *upid)
+#else
 static void free_pidmap(struct upid *upid)
+#endif
 {
+#ifndef CONFIG_KRG_PROC
 	int nr = upid->nr;
+#else
+	int nr = SHORT_PID(upid->nr);
+#endif
 	struct pidmap *map = upid->ns->pidmap + nr / BITS_PER_PAGE;
 	int offset = nr & BITS_PER_PAGE_MASK;
 
@@ -122,6 +138,35 @@ static void free_pidmap(struct upid *upid)
 	atomic_inc(&map->nr_free);
 }
 
+#ifdef CONFIG_KRG_EPM
+static void free_pidmap(struct upid *upid)
+{
+	if ((upid->nr & GLOBAL_PID_MASK)
+	    && ORIG_NODE(upid->nr) != kerrighed_node_id)
+		krg_free_pidmap(upid);
+	else
+		__free_pidmap(upid);
+}
+
+int alloc_pidmap_page(struct pidmap *map)
+{
+	void *page = kzalloc(PAGE_SIZE, GFP_KERNEL);
+	/*
+	 * Free the page if someone raced with us
+	 * installing it:
+	 */
+	spin_lock_irq(&pidmap_lock);
+	if (map->page)
+		kfree(page);
+	else
+		map->page = page;
+	spin_unlock_irq(&pidmap_lock);
+	if (unlikely(!map->page))
+		return -ENOMEM;
+	return 0;
+}
+#endif /* CONFIG_KRG_EPM */
+
 static int alloc_pidmap(struct pid_namespace *pid_ns)
 {
 	int i, offset, max_scan, pid, last = pid_ns->last_pid;
@@ -135,6 +180,9 @@ static int alloc_pidmap(struct pid_namespace *pid_ns)
 	max_scan = (pid_max + BITS_PER_PAGE - 1)/BITS_PER_PAGE - !offset;
 	for (i = 0; i <= max_scan; ++i) {
 		if (unlikely(!map->page)) {
+#ifdef CONFIG_KRG_EPM
+			if (alloc_pidmap_page(map))
+#else
 			void *page = kzalloc(PAGE_SIZE, GFP_KERNEL);
 			/*
 			 * Free the page if someone raced with us
@@ -147,6 +195,7 @@ static int alloc_pidmap(struct pid_namespace *pid_ns)
 				map->page = page;
 			spin_unlock_irq(&pidmap_lock);
 			if (unlikely(!map->page))
+#endif
 				break;
 		}
 		if (likely(atomic_read(&map->nr_free))) {
@@ -182,6 +231,36 @@ static int alloc_pidmap(struct pid_namespace *pid_ns)
 	return -1;
 }
 
+#ifdef CONFIG_KRG_EPM
+int reserve_pidmap(struct pid_namespace *pid_ns, int pid)
+{
+	int offset;
+	struct pidmap *map;
+
+	pid = SHORT_PID(pid);
+	if (pid >= pid_max)
+		return -EINVAL;
+
+	offset = pid & BITS_PER_PAGE_MASK;
+	map = &pid_ns->pidmap[pid/BITS_PER_PAGE];
+	if (!map->page) {
+		/* next_pidmap() is safe if intermediate pages are missing */
+		int err = alloc_pidmap_page(map);
+		if (err)
+			return err;
+	}
+
+	/* Reserve pid in the page */
+	BUG_ON(pid != mk_pid(pid_ns, map, offset));
+	if (!test_and_set_bit(offset, map->page)) {
+		atomic_dec(&map->nr_free);
+		return 0;
+	}
+
+	return -EBUSY;
+}
+#endif /* CONFIG_KRG_EPM */
+
 int next_pidmap(struct pid_namespace *pid_ns, int last)
 {
 	int offset;
@@ -239,7 +318,11 @@ void free_pid(struct pid *pid)
 	call_rcu(&pid->rcu, delayed_put_pid);
 }
 
+#ifdef CONFIG_KRG_EPM
+struct pid *__alloc_pid(struct pid_namespace *ns, const int *req_nr)
+#else
 struct pid *alloc_pid(struct pid_namespace *ns)
+#endif
 {
 	struct pid *pid;
 	enum pid_type type;
@@ -250,12 +333,28 @@ struct pid *alloc_pid(struct pid_namespace *ns)
 	pid = kmem_cache_alloc(ns->pid_cachep, GFP_KERNEL);
 	if (!pid)
 		goto out;
+#ifdef CONFIG_KRG_EPM
+	pid->kddm_obj = NULL;
+	BUG_ON(req_nr && !is_krg_pid_ns_root(ns));
+#endif
 
 	tmp = ns;
 	for (i = ns->level; i >= 0; i--) {
+#ifdef CONFIG_KRG_EPM
+		if (req_nr && tmp == ns) {
+			nr = req_nr[i - tmp->level];
+		} else {
+#endif
 		nr = alloc_pidmap(tmp);
 		if (nr < 0)
 			goto out_free;
+#ifdef CONFIG_KRG_PROC
+		if (tmp->global && nr != 1)
+			nr = GLOBAL_PID(nr);
+#endif
+#ifdef CONFIG_KRG_EPM
+		}
+#endif
 
 		pid->numbers[i].nr = nr;
 		pid->numbers[i].ns = tmp;
@@ -267,6 +366,10 @@ struct pid *alloc_pid(struct pid_namespace *ns)
 	atomic_set(&pid->count, 1);
 	for (type = 0; type < PIDTYPE_MAX; ++type)
 		INIT_HLIST_HEAD(&pid->tasks[type]);
+#ifdef CONFIG_KRG_SCHED
+	for (type = 0; type < PIDTYPE_MAX; ++type)
+		INIT_HLIST_HEAD(&pid->process_sets[type]);
+#endif
 
 	spin_lock_irq(&pidmap_lock);
 	for (i = ns->level; i >= 0; i--) {
@@ -280,6 +383,9 @@ out:
 	return pid;
 
 out_free:
+#ifdef CONFIG_KRG_EPM
+	BUG_ON(req_nr);
+#endif
 	while (++i <= ns->level)
 		free_pidmap(pid->numbers + i);
 
@@ -305,7 +411,7 @@ EXPORT_SYMBOL_GPL(find_pid_ns);
 
 struct pid *find_vpid(int nr)
 {
-	return find_pid_ns(nr, current->nsproxy->pid_ns);
+	return find_pid_ns(nr, task_active_pid_ns(current));
 }
 EXPORT_SYMBOL_GPL(find_vpid);
 
@@ -339,7 +445,11 @@ static void __change_pid(struct task_struct *task, enum pid_type type,
 		if (!hlist_empty(&pid->tasks[tmp]))
 			return;
 
+#ifdef CONFIG_KRG_EPM
+	krg_put_pid(pid);
+#else
 	free_pid(pid);
+#endif
 }
 
 void detach_pid(struct task_struct *task, enum pid_type type)
@@ -389,7 +499,7 @@ EXPORT_SYMBOL(find_task_by_pid_type_ns);
 struct task_struct *find_task_by_vpid(pid_t vnr)
 {
 	return find_task_by_pid_type_ns(PIDTYPE_PID, vnr,
-			current->nsproxy->pid_ns);
+					task_active_pid_ns(current));
 }
 EXPORT_SYMBOL(find_task_by_vpid);
 
@@ -445,10 +555,13 @@ pid_t pid_nr_ns(struct pid *pid, struct pid_namespace *ns)
 	}
 	return nr;
 }
+#ifdef CONFIG_KRG_PROC
+EXPORT_SYMBOL(pid_nr_ns);
+#endif
 
 pid_t pid_vnr(struct pid *pid)
 {
-	return pid_nr_ns(pid, current->nsproxy->pid_ns);
+	return pid_nr_ns(pid, task_active_pid_ns(current));
 }
 EXPORT_SYMBOL_GPL(pid_vnr);
 
@@ -459,7 +572,7 @@ pid_t __task_pid_nr_ns(struct task_struct *task, enum pid_type type,
 
 	rcu_read_lock();
 	if (!ns)
-		ns = current->nsproxy->pid_ns;
+		ns = task_active_pid_ns(current);
 	if (likely(pid_alive(task))) {
 		if (type != PIDTYPE_PID)
 			task = task->group_leader;
@@ -491,16 +604,57 @@ EXPORT_SYMBOL_GPL(task_active_pid_ns);
 struct pid *find_ge_pid(int nr, struct pid_namespace *ns)
 {
 	struct pid *pid;
+#ifdef CONFIG_KRG_PROC
+	int global = (nr & GLOBAL_PID_MASK) && ns->global;
+#endif
 
 	do {
+#ifdef CONFIG_KRG_PROC
+		if (global && !(nr & GLOBAL_PID_MASK))
+			nr = GLOBAL_PID(nr);
+#endif
 		pid = find_pid_ns(nr, ns);
 		if (pid)
 			break;
+#ifdef CONFIG_KRG_PROC
+		if (global) {
+			if (ORIG_NODE(nr) != kerrighed_node_id)
+				break;
+			nr = SHORT_PID(nr);
+		}
+#endif
 		nr = next_pidmap(ns, nr);
 	} while (nr > 0);
+#ifdef CONFIG_KRG_PROC
+	if (nr <= 0 && !global && ns->global)
+		return find_ge_pid(GLOBAL_PID(0), ns);
+#endif
+
+	return pid;
+}
+
+#ifdef CONFIG_KRG_PROC
+struct pid *krg_find_ge_pid(int nr, struct pid_namespace *pid_ns,
+			    struct pid_namespace *pidmap_ns)
+{
+	kerrighed_node_t node = ORIG_NODE(nr);
+	struct pid *pid;
+
+	BUG_ON(!pid_ns->global);
+	BUG_ON(!(nr & GLOBAL_PID_MASK));
+
+	do {
+		pid = find_pid_ns(nr, pid_ns);
+		if (pid)
+			break;
+		nr = next_pidmap(pidmap_ns, SHORT_PID(nr));
+		if (nr > 0)
+			nr = GLOBAL_PID_NODE(nr, node);
+	} while (nr > 0);
 
 	return pid;
 }
+#endif /* CONFIG_KRG_PROC */
 
 /*
  * The pid hash table is scaled according to the amount of memory in the
diff --git a/kernel/pid_namespace.c b/kernel/pid_namespace.c
index 2d1001b..cc56094 100644
