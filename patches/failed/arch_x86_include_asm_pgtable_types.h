--- a/arch/x86/include/asm/pgtable_types.h
+++ b/arch/x86/include/asm/pgtable_types.h
@@ -25,10 +25,22 @@
 #define _PAGE_BIT_NX           63       /* No execute: only valid after cpuid check */
 
 /* If _PAGE_BIT_PRESENT is clear, we use these: */
+#ifdef CONFIG_KRG_MM
+
+/* | Offset | Swap device (5 bits) | FILE    | PROT_NONE     | OBJ_ENTRY = 0| PRESENT = 0| */
+/* | ObjEntry address              | FILE = 0| PROT_NONE = 0 | OBJ_ENTRY = 1| PRESENT = 0| */
+#define _PAGE_BIT_OBJ_ENTRY	1
+#define _PAGE_BIT_PROTNONE	2
+#define _PAGE_BIT_FILE		3
+
+/* while standard Linux is */
+/* | Offset                   |PROT_NONE  |  FILE    | Swap device (6 bits) | PRESENT = 0| */
+#else
 /* - if the user mapped it with PROT_NONE; pte_present gives true */
 #define _PAGE_BIT_PROTNONE	_PAGE_BIT_GLOBAL
 /* - set: nonlinear file mapping, saved PTE; unset:swap */
 #define _PAGE_BIT_FILE		_PAGE_BIT_DIRTY
+#endif
 
 #define _PAGE_PRESENT	(_AT(pteval_t, 1) << _PAGE_BIT_PRESENT)
 #define _PAGE_RW	(_AT(pteval_t, 1) << _PAGE_BIT_RW)
@@ -56,6 +68,9 @@
 
 #define _PAGE_FILE	(_AT(pteval_t, 1) << _PAGE_BIT_FILE)
 #define _PAGE_PROTNONE	(_AT(pteval_t, 1) << _PAGE_BIT_PROTNONE)
+#ifdef CONFIG_KRG_MM
+#define _PAGE_OBJ_ENTRY (_AT(pteval_t, 1) << _PAGE_BIT_OBJ_ENTRY)
+#endif
 
 #define _PAGE_TABLE	(_PAGE_PRESENT | _PAGE_RW | _PAGE_USER |	\
 			 _PAGE_ACCESSED | _PAGE_DIRTY)
diff --git a/arch/x86/include/asm/processor.h b/arch/x86/include/asm/processor.h
index c2cceae..06f4625 100644
