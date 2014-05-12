--- a/arch/x86/kernel/cpu/proc.c
+++ b/arch/x86/kernel/cpu/proc.c
@@ -13,8 +13,11 @@ static void show_cpuinfo_core(struct seq_file *m, struct cpuinfo_x86 *c,
 #ifdef CONFIG_SMP
 	if (c->x86_max_cores * smp_num_siblings > 1) {
 		seq_printf(m, "physical id\t: %d\n", c->phys_proc_id);
+#ifndef CONFIG_KRG_PROCFS
+		/* TODO: implement support for cpu_core_map */
 		seq_printf(m, "siblings\t: %d\n",
 			   cpumask_weight(cpu_core_mask(cpu)));
+#endif
 		seq_printf(m, "core id\t\t: %d\n", c->cpu_core_id);
 		seq_printf(m, "cpu cores\t: %d\n", c->booted_cores);
 		seq_printf(m, "apicid\t\t: %d\n", c->apicid);
@@ -70,6 +73,10 @@ static int show_cpuinfo(struct seq_file *m, void *v)
 #ifdef CONFIG_SMP
 	cpu = c->cpu_index;
 #endif
+#ifdef CONFIG_KRG_PROCFS
+	if (m->op != &cpuinfo_op)
+		cpu = c->krg_cpu_id;
+#endif
 	seq_printf(m, "processor\t: %u\n"
 		   "vendor_id\t: %s\n"
 		   "cpu family\t: %d\n"
@@ -87,10 +94,15 @@ static int show_cpuinfo(struct seq_file *m, void *v)
 		seq_printf(m, "stepping\t: unknown\n");
 
 	if (cpu_has(c, X86_FEATURE_TSC)) {
+#ifdef CONFIG_KRG_PROCFS
+		/* TODO: implement support for cpufreq */
+		unsigned int freq = ((m->op == &cpuinfo_op) ? cpu_khz : c->cpu_khz);
+#else
 		unsigned int freq = cpufreq_quick_get(cpu);
 
 		if (!freq)
 			freq = cpu_khz;
+#endif
 		seq_printf(m, "cpu MHz\t\t: %u.%03u\n",
 			   freq / 1000, (freq % 1000));
 	}
diff --git a/arch/x86/kernel/entry_64.S b/arch/x86/kernel/entry_64.S
index 38946c6..8f6f065 100644
