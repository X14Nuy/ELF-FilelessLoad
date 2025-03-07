	.text
	.globl	z_trampo
	.type	z_trampo,%function
z_trampo:
	mov	r4, r0 /* 入口地址 */
	mov	sp, r1 /* 栈顶地址 */
	mov r0, r2
	bx	r4
	/* Should not reach. */   
	hlt