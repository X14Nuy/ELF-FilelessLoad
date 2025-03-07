	.text
	.globl 	z_start
	.hidden z_start
	.type	z_start,%function
z_start:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	mov		r0, sp
	mov		r1, r0 /* 瞎写，用不上fini */
	bl		z_entry
	pop		{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	hlt