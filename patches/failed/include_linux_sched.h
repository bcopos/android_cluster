--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -88,6 +88,12 @@ struct sched_param {
 #include <linux/kobject.h>
 #include <linux/latencytop.h>
 #include <linux/cred.h>
+#ifdef CONFIG_KRG_CAP
+#include <kerrighed/capabilities.h>
+#endif
+#ifdef CONFIG_KRG_EPM
+#include <kddm/kddm_types.h>
+#endif
 
 #include <asm/processor.h>
 
@@ -185,6 +191,10 @@ extern unsigned long long time_sync_thresh;
 /* in tsk->state again */
 #define TASK_DEAD		64
 #define TASK_WAKEKILL		128
+#ifdef CONFIG_KRG_EPM
+/* in tsk->exit_state */
+#define EXIT_MIGRATION		256
+#endif
 
 /* Convenience macros for the sake of set_task_state */
 #define TASK_KILLABLE		(TASK_WAKEKILL | TASK_UNINTERRUPTIBLE)
@@ -444,6 +454,10 @@ struct sighand_struct {
 	struct k_sigaction	action[_NSIG];
 	spinlock_t		siglock;
 	wait_queue_head_t	signalfd_wqh;
+#ifdef CONFIG_KRG_EPM
+	objid_t			krg_objid;
+	struct sighand_struct_kddm_object *kddm_obj;
+#endif
 };
 
 struct pacct_struct {
@@ -604,6 +618,10 @@ struct signal_struct {
 	unsigned audit_tty;
 	struct tty_audit_buf *tty_audit_buf;
 #endif
+#ifdef CONFIG_KRG_EPM
+	objid_t krg_objid;
+	struct signal_struct_kddm_object *kddm_obj;
+#endif
 };
 
 /* Context switch must be unlocked if interrupts are to be enabled */
@@ -1181,6 +1199,12 @@ struct task_struct {
 	unsigned did_exec:1;
 	unsigned in_execve:1;	/* Tell the LSMs that the process is doing an
 				 * execve */
+#ifdef CONFIG_KRG_HOTPLUG
+	unsigned create_krg_ns:1;
+#endif
+#ifdef CONFIG_KRG_EPM
+	unsigned remote_vfork_done:1;
+#endif
 	pid_t pid;
 	pid_t tgid;
 
@@ -1429,6 +1453,28 @@ struct task_struct {
 	/* state flags for use by tracers */
 	unsigned long trace;
 #endif
+#ifdef CONFIG_KRG_CAP
+	kernel_krg_cap_t krg_caps;
+	atomic_t krg_cap_used[CAP_SIZE];
+	atomic_t krg_cap_unavailable[CAP_SIZE];
+	atomic_t krg_cap_unavailable_private[CAP_SIZE];
+#endif
+#ifdef CONFIG_KRG_KDDM
+	struct kddm_info_struct *kddm_info;
+#endif
+#ifdef CONFIG_KRG_PROC
+	struct task_kddm_object *task_obj;
+#endif
+#ifdef CONFIG_KRG_EPM
+	int krg_action_flags;
+	struct task_struct *effective_current;
+	struct children_kddm_object *parent_children_obj;
+	struct children_kddm_object *children_obj;
+	struct app_struct *application;
+#endif
+#ifdef CONFIG_KRG_SCHED
+	struct krg_sched_info *krg_sched;
+#endif
 };
 
 /* Future-safe accessor for struct task_struct's cpus_allowed. */
@@ -1617,12 +1663,22 @@ extern cputime_t task_gtime(struct task_struct *p);
 /*
  * Per process flags
  */
+#ifdef CONFIG_KRG_EPM
+/* PF_ALIGNWARN is unused */
+#define PF_DELAY_NOTIFY	0x00000001	/* must do_notify_parent() before can be */
+					/* reaped */
+#else
 #define PF_ALIGNWARN	0x00000001	/* Print alignment warning msgs */
 					/* Not implemented yet, only for 486*/
+#endif
 #define PF_STARTING	0x00000002	/* being created */
 #define PF_EXITING	0x00000004	/* getting shut down */
 #define PF_EXITPIDONE	0x00000008	/* pi exit done on shut down */
 #define PF_VCPU		0x00000010	/* I'm a virtual CPU */
+#ifdef CONFIG_KRG_EPM
+#define PF_AWAY		0x00000020	/* I don't want to be considered as local */
+					/* by my relatives */
+#endif
 #define PF_FORKNOEXEC	0x00000040	/* forked but didn't exec */
 #define PF_SUPERPRIV	0x00000100	/* used super-user privileges */
 #define PF_DUMPCORE	0x00000200	/* dumped core */
@@ -1834,6 +1890,10 @@ extern struct   mm_struct init_mm;
 
 extern struct pid_namespace init_pid_ns;
 
+#ifdef CONFIG_KRG_EPM
+extern struct task_struct *baby_sitter;
+#endif
+
 /*
  * find a task by one of its numerical ids
  *
@@ -1919,6 +1979,11 @@ extern void force_sig(int, struct task_struct *);
 extern void force_sig_specific(int, struct task_struct *);
 extern int send_sig(int, struct task_struct *, int);
 extern void zap_other_threads(struct task_struct *p);
+#ifdef CONFIG_KRG_EPM
+extern struct sigqueue *__sigqueue_alloc(struct task_struct *t, gfp_t flags,
+					 int override_rlimit);
+extern void __sigqueue_free(struct sigqueue *q);
+#endif
 extern struct sigqueue *sigqueue_alloc(void);
 extern void sigqueue_free(struct sigqueue *);
 extern int send_sigqueue(struct sigqueue *,  struct task_struct *, int group);
@@ -1987,6 +2052,11 @@ extern void __cleanup_sighand(struct sighand_struct *);
 extern void exit_itimers(struct signal_struct *);
 extern void flush_itimer_signals(void);
 
+#ifdef CONFIG_KRG_EPM
+int wait_task_zombie(struct task_struct *p, int options,
+		     struct siginfo __user *infop,
+		     int __user *stat_addr, struct rusage __user *ru);
+#endif
 extern NORET_TYPE void do_group_exit(int);
 
 extern void daemonize(const char *, ...);
@@ -1996,6 +2066,26 @@ extern int disallow_signal(int);
 extern int do_execve(char *, char __user * __user *, char __user * __user *, struct pt_regs *);
 extern long do_fork(unsigned long, unsigned long, struct pt_regs *, unsigned long, int __user *, int __user *);
 struct task_struct *fork_idle(int);
+#ifdef CONFIG_KRG_EPM
+struct task_struct *copy_process(unsigned long clone_flags,
+				 unsigned long stack_start,
+				 struct pt_regs *regs,
+				 unsigned long stack_size,
+				 int __user *child_tidptr,
+				 struct pid *pid,
+				 int trace);
+/* remote clone */
+int krg_do_fork(unsigned long clone_flags,
+		unsigned long stack_start,
+		struct pt_regs *regs,
+		unsigned long stack_size,
+		int *parent_tidptr,
+		int *child_tidptr,
+		int trace);
+bool in_krg_do_fork(void);
+/* vfork with remote child */
+void krg_vfork_done(struct completion *vfork_done);
+#endif /* CONFIG_KRG_EPM */
 
 extern void set_task_comm(struct task_struct *tsk, char *from);
 extern char *get_task_comm(char *to, struct task_struct *tsk);
@@ -2269,6 +2359,9 @@ static inline void thread_group_cputime_free(struct signal_struct *sig)
  * callers must hold sighand->siglock.
  */
 extern void recalc_sigpending_and_wake(struct task_struct *t);
+#ifdef CONFIG_KRG_EPM
+extern int recalc_sigpending_tsk(struct task_struct *t);
+#endif
 extern void recalc_sigpending(void);
 
 extern void signal_wake_up(struct task_struct *t, int resume_stopped);
diff --git a/include/linux/sem.h b/include/linux/sem.h
index 1b191c1..2e134e8 100644
