--- a/arch/x86/include/asm/uaccess.h
+++ b/arch/x86/include/asm/uaccess.h
@@ -186,6 +186,34 @@ extern int __get_user_bad(void);
 
 
 #ifdef CONFIG_X86_32
+#ifdef CONFIG_KRG_FAF
+
+#define __put_user_asm_u64(x, addr, err, errret)			\
+	asm volatile("1:	movl %%eax,0(%2)\n"			\
+		     "2:	movl %%edx,4(%2)\n"			\
+		     "3:\n"						\
+		     ".section .fixup,\"ax\"\n"				\
+		     "4:	subl $4,%%esp\n"			\
+		     "  movl $8,(%%esp)\n"				\
+		     "	pushl %%edx\n"					\
+		     "	pushl %%eax\n"					\
+		     "	movl %2,%%eax\n"					\
+		     "	call ruaccess_put_user_asm\n"			\
+		     "	testl %%eax,%%eax\n"				\
+		     "	popl %%eax\n"					\
+		     "	popl %%edx\n"					\
+		     "	lea 4(%%esp),%%esp\n"				\
+		     "	jz 3b\n"					\
+		     "5:	movl %3,%0\n"				\
+		     "	jmp 3b\n"					\
+		     ".previous\n"					\
+		     _ASM_EXTABLE(1b, 4b)				\
+		     _ASM_EXTABLE(2b, 5b)				\
+		     : "=r" (err)					\
+		     : "A" (x), "r" (addr), "i" (errret), "0" (err))
+
+#else /* !CONFIG_KRG_FAF */
+
 #define __put_user_asm_u64(x, addr, err, errret)			\
 	asm volatile("1:	movl %%eax,0(%2)\n"			\
 		     "2:	movl %%edx,4(%2)\n"			\
@@ -199,6 +227,8 @@ extern int __get_user_bad(void);
 		     : "=r" (err)					\
 		     : "A" (x), "r" (addr), "i" (errret), "0" (err))
 
+#endif /* !CONFIG_KRG_FAF */
+
 #define __put_user_asm_ex_u64(x, addr)					\
 	asm volatile("1:	movl %%eax,0(%1)\n"			\
 		     "2:	movl %%edx,4(%1)\n"			\
@@ -373,6 +403,37 @@ do {									\
 	}								\
 } while (0)
 
+#ifdef CONFIG_KRG_FAF
+
+extern int ruaccess_get_user_asm(void);
+
+#define __get_user_asm(x, addr, err, itype, rtype, ltype, errret)	\
+	asm volatile("1:	mov"itype" %2,%"rtype"1\n"		\
+		     "2:\n"						\
+		     ".section .fixup,\"ax\"\n"				\
+		     "3:	sub $16,%%"_ASM_SP"\n"			\
+		     "	push %%"_ASM_AX"\n"				\
+		     "	"_ASM_MOV" %5,16(%%"_ASM_SP")\n"		\
+		     "	lea %2,%%"_ASM_AX"\n"				\
+		     "	call ruaccess_get_user_asm\n"			\
+		     "	testl %%eax,%%eax\n"				\
+		     "	pop %%"_ASM_AX"\n"				\
+		     "	jnz 4f\n"					\
+		     "	mov"itype" (%%"_ASM_SP"),%"rtype"1\n"		\
+		     "	add $16,%%"_ASM_SP"\n"				\
+		     "	jmp 2b\n"					\
+		     "4:	add $16,%%"_ASM_SP"\n"			\
+		     "	mov %3,%0\n"					\
+		     "	xor"itype" %"rtype"1,%"rtype"1\n"		\
+		     "	jmp 2b\n"					\
+		     ".previous\n"					\
+		     _ASM_EXTABLE(1b, 3b)				\
+		     : "=r" (err), ltype (x)				\
+		     : "m" (__m(addr)), "i" (errret), "0" (err),	\
+		       "i" (sizeof(*(addr))))
+
+#else /* !CONFIG_KRG_FAF */
+
 #define __get_user_asm(x, addr, err, itype, rtype, ltype, errret)	\
 	asm volatile("1:	mov"itype" %2,%"rtype"1\n"		\
 		     "2:\n"						\
@@ -385,6 +446,8 @@ do {									\
 		     : "=r" (err), ltype(x)				\
 		     : "m" (__m(addr)), "i" (errret), "0" (err))
 
+#endif /* !CONFIG_KRG_FAF */
+
 #define __get_user_size_ex(x, ptr, size)				\
 do {									\
 	__chk_user_ptr(ptr);						\
@@ -437,6 +500,34 @@ struct __large_struct { unsigned long buf[100]; };
  * we do not write to any memory gcc knows about, so there are no
  * aliasing issues.
  */
+#ifdef CONFIG_KRG_FAF
+
+extern int ruaccess_put_user_asm(void);
+
+#define __put_user_asm(x, addr, err, itype, rtype, ltype, errret)	\
+	asm volatile("1:	mov"itype" %"rtype"1,%2\n"		\
+		     "2:\n"						\
+		     ".section .fixup,\"ax\"\n"				\
+		     "3:	push %%"_ASM_AX"\n"			\
+		     "	sub $16,%%"_ASM_SP"\n"				\
+		     "	mov"itype" %"rtype"1,(%%"_ASM_SP")\n"		\
+		     "	"_ASM_MOV" %5,8(%%"_ASM_SP")\n"			\
+		     "	lea %2,%%"_ASM_AX"\n"				\
+		     "	call ruaccess_put_user_asm\n"			\
+		     "	add $16,%%"_ASM_SP"\n"				\
+		     "	testl %%eax,%%eax\n"				\
+		     "	pop %%"_ASM_AX"\n"				\
+		     "	jz 2b\n"					\
+		     "	mov %3,%0\n"					\
+		     "	jmp 2b\n"					\
+		     ".previous\n"					\
+		     _ASM_EXTABLE(1b, 3b)				\
+		     : "=r"(err)					\
+		     : ltype(x), "m" (__m(addr)), "i" (errret), "0" (err), \
+		       "i" (sizeof(*(addr))))
+
+#else /* CONFIG_KRG_FAF */
+
 #define __put_user_asm(x, addr, err, itype, rtype, ltype, errret)	\
 	asm volatile("1:	mov"itype" %"rtype"1,%2\n"		\
 		     "2:\n"						\
@@ -448,6 +539,8 @@ struct __large_struct { unsigned long buf[100]; };
 		     : "=r"(err)					\
 		     : ltype(x), "m" (__m(addr)), "i" (errret), "0" (err))
 
+#endif /* CONFIG_KRG_FAF */
+
 #define __put_user_asm_ex(x, addr, itype, rtype, ltype)			\
 	asm volatile("1:	mov"itype" %"rtype"0,%1\n"		\
 		     "2:\n"						\
@@ -565,6 +658,18 @@ extern struct movsl_mask {
 } ____cacheline_aligned_in_smp movsl_mask;
 #endif
 
+#ifdef CONFIG_KRG_FAF
+static inline int check_ruaccess(void)
+{
+	struct thread_info *ti = current_thread_info();
+	return (unlikely(test_ti_thread_flag(ti, TIF_RUACCESS))
+		&& segment_eq(ti->addr_limit, USER_DS));
+}
+
+#define ARCH_HAS_RUACCESS
+#define ARCH_HAS_RUACCESS_FIXUP
+#endif /* CONFIG_KRG_FAF */
+
 #define ARCH_HAS_NOCACHE_UACCESS 1
 
 #ifdef CONFIG_X86_32
diff --git a/arch/x86/include/asm/uaccess_32.h b/arch/x86/include/asm/uaccess_32.h
index 5e06259..4679f9c 100644
