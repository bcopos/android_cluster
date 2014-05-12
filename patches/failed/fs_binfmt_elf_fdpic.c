--- a/fs/binfmt_elf_fdpic.c
+++ b/fs/binfmt_elf_fdpic.c
@@ -34,6 +34,10 @@
 #include <linux/elf.h>
 #include <linux/elf-fdpic.h>
 #include <linux/elfcore.h>
+#ifdef CONFIG_KRG_EPM
+#include <kerrighed/children.h>
+#include <kerrighed/krgsyms.h>
+#endif
 
 #include <asm/uaccess.h>
 #include <asm/param.h>
@@ -90,11 +94,24 @@ static struct linux_binfmt elf_fdpic_format = {
 
 static int __init init_elf_fdpic_binfmt(void)
 {
+#ifdef CONFIG_KRG_EPM
+	int retval;
+
+	krgsyms_register(KRGSYMS_BINFMTS_ELF_FDPIC, &elf_fdpic_format);
+	retval = register_binfmt(&elf_fdpic_format);
+	if (retval)
+		krgsyms_unregister(KRGSYMS_BINFMTS_ELF_FDPIC);
+	return retval;
+#else
 	return register_binfmt(&elf_fdpic_format);
+#endif
 }
 
 static void __exit exit_elf_fdpic_binfmt(void)
 {
+#ifdef CONFIG_KRG_EPM
+	krgsyms_unregister(KRGSYMS_BINFMTS_ELF_FDPIC);
+#endif
 	unregister_binfmt(&elf_fdpic_format);
 }
 
@@ -1388,7 +1405,11 @@ static void fill_prstatus(struct elf_prstatus *prstatus,
 	prstatus->pr_sigpend = p->pending.signal.sig[0];
 	prstatus->pr_sighold = p->blocked.sig[0];
 	prstatus->pr_pid = task_pid_vnr(p);
+#ifdef CONFIG_KRG_EPM
+	prstatus->pr_ppid = krg_get_real_parent_pid(p);
+#else
 	prstatus->pr_ppid = task_pid_vnr(p->real_parent);
+#endif
 	prstatus->pr_pgrp = task_pgrp_vnr(p);
 	prstatus->pr_sid = task_session_vnr(p);
 	if (thread_group_leader(p)) {
@@ -1433,7 +1454,11 @@ static int fill_psinfo(struct elf_prpsinfo *psinfo, struct task_struct *p,
 	psinfo->pr_psargs[len] = 0;
 
 	psinfo->pr_pid = task_pid_vnr(p);
+#ifdef CONFIG_KRG_EPM
+	psinfo->pr_ppid = krg_get_real_parent_pid(p);
+#else
 	psinfo->pr_ppid = task_pid_vnr(p->real_parent);
+#endif
 	psinfo->pr_pgrp = task_pgrp_vnr(p);
 	psinfo->pr_sid = task_session_vnr(p);
 
diff --git a/fs/binfmt_em86.c b/fs/binfmt_em86.c
index 32fb00b..5f352ef 100644
