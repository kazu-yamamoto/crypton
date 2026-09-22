.text	



.globl	crypton_poly1305_asm_init

.globl	crypton_poly1305_asm_blocks

.globl	crypton_poly1305_asm_emit


.def	crypton_poly1305_asm_init;	.scl 2;	.type 32;	.endef
.p2align	5
crypton_poly1305_asm_init:
	.byte	0xf3,0x0f,0x1e,0xfa
	movq	%rdi,8(%rsp)
	movq	%rsi,16(%rsp)
	movq	%rsp,%rax
.LSEH_begin_crypton_poly1305_asm_init:

	movq	%rcx,%rdi
	movq	%rdx,%rsi
	movq	%r8,%rdx
	xorq	%rax,%rax
	movq	%rax,0(%rdi)
	movq	%rax,8(%rdi)
	movq	%rax,16(%rdi)

	cmpq	$0,%rsi
	je	.Lno_key

	movq	$0x0ffffffc0fffffff,%rax
	leaq	-3(%rax),%rcx
	andq	0(%rsi),%rax
	andq	8(%rsi),%rcx
	movq	%rax,24(%rdi)
	movq	%rcx,32(%rdi)
	movl	$-1,48(%rdi)
	leaq	crypton_poly1305_asm_blocks(%rip),%r10
	leaq	crypton_poly1305_asm_emit(%rip),%r11
	movq	crypton_ia32cap_P+4(%rip),%r9
	leaq	crypton_poly1305_asm_blocks_avx(%rip),%rax
	btq	$28,%r9
	cmovcq	%rax,%r10
	leaq	crypton_poly1305_asm_blocks_avx2(%rip),%rax
	btq	$37,%r9
	cmovcq	%rax,%r10
	movq	%r10,0(%rdx)
	movq	%r11,8(%rdx)
	movl	$1,%eax
.Lno_key:
	movq	8(%rsp),%rdi
	movq	16(%rsp),%rsi
	.byte	0xf3,0xc3
.LSEH_end_crypton_poly1305_asm_init:

.def	crypton_poly1305_asm_blocks;	.scl 2;	.type 32;	.endef
.p2align	5
crypton_poly1305_asm_blocks:
	.byte	0xf3,0x0f,0x1e,0xfa
	movq	%rdi,8(%rsp)
	movq	%rsi,16(%rsp)
	movq	%rsp,%rax
.LSEH_begin_crypton_poly1305_asm_blocks:


	movq	%rcx,%rdi
	movq	%rdx,%rsi
	movq	%r8,%rdx
	movq	%r9,%rcx
.Lblocks:
	shrq	$4,%rdx
	jz	.Lno_data

	pushq	%rbx

	pushq	%rbp

	pushq	%r12

	pushq	%r13

	pushq	%r14

	pushq	%r15

	leaq	-8(%rsp),%rsp

.Lblocks_body:

	movq	%rdx,%r15

	movq	24(%rdi),%r11
	movq	32(%rdi),%r13

	movq	0(%rdi),%r14
	movq	8(%rdi),%rbx
	movq	16(%rdi),%rbp

	movl	%r14d,%eax
	movl	4(%rdi),%edx
	movl	%ebx,%r8d
	movl	12(%rdi),%r10d
	movl	%ebp,%r12d

	shlq	$26,%rdx
	movq	%r8,%r9
	shlq	$52,%r8
	addq	%rdx,%rax
	shrq	$12,%r9
	addq	%rax,%r8
	adcq	$0,%r9

	shlq	$14,%r10
	movq	%r12,%rax
	shrq	$24,%r12
	addq	%r10,%r9
	shlq	$40,%rax
	addq	%rax,%r9
	adcq	$0,%r12

	cmpq	$4,%rbp

	cmovaq	%r8,%r14
	cmovaq	%r9,%rbx
	cmovaq	%r12,%rbp

	movq	%r13,%r12
	shrq	$2,%r13
	movq	%r12,%rax
	addq	%r12,%r13
	jmp	.Loop

.p2align	5
.Loop:
	addq	0(%rsi),%r14
	adcq	8(%rsi),%rbx
	leaq	16(%rsi),%rsi
	adcq	%rcx,%rbp
	mulq	%r14
	movq	%rax,%r9
	movq	%r11,%rax
	movq	%rdx,%r10

	mulq	%r14
	movq	%rax,%r14
	movq	%r11,%rax
	movq	%rdx,%r8

	mulq	%rbx
	addq	%rax,%r9
	movq	%r13,%rax
	adcq	%rdx,%r10

	mulq	%rbx
	movq	%rbp,%rbx
	addq	%rax,%r14
	adcq	%rdx,%r8

	imulq	%r13,%rbx
	addq	%rbx,%r9
	movq	%r8,%rbx
	adcq	$0,%r10

	imulq	%r11,%rbp
	addq	%r9,%rbx
	movq	$-4,%rax
	adcq	%rbp,%r10

	andq	%r10,%rax
	movq	%r10,%rbp
	shrq	$2,%r10
	andq	$3,%rbp
	addq	%r10,%rax
	addq	%rax,%r14
	adcq	$0,%rbx
	adcq	$0,%rbp
	movq	%r12,%rax
	decq	%r15
	jnz	.Loop

	movq	%r14,0(%rdi)
	movq	%rbx,8(%rdi)
	movq	%rbp,16(%rdi)

	movq	8(%rsp),%r15

	movq	16(%rsp),%r14

	movq	24(%rsp),%r13

	movq	32(%rsp),%r12

	movq	40(%rsp),%rbp

	movq	48(%rsp),%rbx

	leaq	56(%rsp),%rsp

.Lno_data:
.Lblocks_epilogue:
	movq	8(%rsp),%rdi
	movq	16(%rsp),%rsi
	.byte	0xf3,0xc3

.LSEH_end_crypton_poly1305_asm_blocks:

.def	crypton_poly1305_asm_emit;	.scl 2;	.type 32;	.endef
.p2align	5
crypton_poly1305_asm_emit:
	.byte	0xf3,0x0f,0x1e,0xfa
	movq	%rdi,8(%rsp)
	movq	%rsi,16(%rsp)
	movq	%rsp,%rax
.LSEH_begin_crypton_poly1305_asm_emit:

	movq	%rcx,%rdi
	movq	%rdx,%rsi
	movq	%r8,%rdx
	movl	0(%rdi),%eax
	movl	4(%rdi),%ecx
	movl	8(%rdi),%r8d
	movl	12(%rdi),%r11d
	movl	16(%rdi),%r10d

	shlq	$26,%rcx
	movq	%r8,%r9
	shlq	$52,%r8
	addq	%rcx,%rax
	shrq	$12,%r9
	addq	%rax,%r8
	adcq	$0,%r9

	shlq	$14,%r11
	movq	%r10,%rax
	shrq	$24,%r10
	addq	%r11,%r9
	movq	0(%rdi),%rcx
	shlq	$40,%rax
	movq	8(%rdi),%r11
	addq	%rax,%r9
	movq	16(%rdi),%rax
	adcq	$0,%r10

	cmpq	$4,%rax

	cmovbeq	%rcx,%r8
	cmovbeq	%r11,%r9
	cmovbeq	%rax,%r10

	movq	%r8,%rax
	addq	$5,%r8
	movq	%r9,%rcx
	adcq	$0,%r9
	adcq	$0,%r10
	shrq	$2,%r10
	cmovnzq	%r8,%rax
	cmovnzq	%r9,%rcx

	addq	0(%rdx),%rax
	adcq	8(%rdx),%rcx
	movq	%rax,0(%rsi)
	movq	%rcx,8(%rsi)

	movq	8(%rsp),%rdi
	movq	16(%rsp),%rsi
	.byte	0xf3,0xc3
.LSEH_end_crypton_poly1305_asm_emit:
.def	__crypton_poly1305_asm_block;	.scl 3;	.type 32;	.endef
.p2align	5
__crypton_poly1305_asm_block:
	.byte	0xf3,0x0f,0x1e,0xfa

	mulq	%r14
	movq	%rax,%r9
	movq	%r11,%rax
	movq	%rdx,%r10

	mulq	%r14
	movq	%rax,%r14
	movq	%r11,%rax
	movq	%rdx,%r8

	mulq	%rbx
	addq	%rax,%r9
	movq	%r13,%rax
	adcq	%rdx,%r10

	mulq	%rbx
	movq	%rbp,%rbx
	addq	%rax,%r14
	adcq	%rdx,%r8

	imulq	%r13,%rbx
	addq	%rbx,%r9
	movq	%r8,%rbx
	adcq	$0,%r10

	imulq	%r11,%rbp
	addq	%r9,%rbx
	movq	$-4,%rax
	adcq	%rbp,%r10

	andq	%r10,%rax
	movq	%r10,%rbp
	shrq	$2,%r10
	andq	$3,%rbp
	addq	%r10,%rax
	addq	%rax,%r14
	adcq	$0,%rbx
	adcq	$0,%rbp
	.byte	0xf3,0xc3


.def	__crypton_poly1305_asm_init_avx;	.scl 3;	.type 32;	.endef
.p2align	5
__crypton_poly1305_asm_init_avx:
	.byte	0xf3,0x0f,0x1e,0xfa

	cmpl	$-1,48(%rdi)
	jne	.Ldone_init_avx

	movq	%r11,%r14
	movq	%r12,%rbx
	xorq	%rbp,%rbp

	leaq	48+64(%rdi),%rdi

	movq	%r12,%rax
	call	__crypton_poly1305_asm_block

	movl	$0x3ffffff,%eax
	movl	$0x3ffffff,%edx
	movq	%r14,%r8
	andl	%r14d,%eax
	movq	%r11,%r9
	andl	%r11d,%edx
	movl	%eax,-64(%rdi)
	shrq	$26,%r8
	movl	%edx,-60(%rdi)
	shrq	$26,%r9

	movl	$0x3ffffff,%eax
	movl	$0x3ffffff,%edx
	andl	%r8d,%eax
	andl	%r9d,%edx
	movl	%eax,-48(%rdi)
	leal	(%rax,%rax,4),%eax
	movl	%edx,-44(%rdi)
	leal	(%rdx,%rdx,4),%edx
	movl	%eax,-32(%rdi)
	shrq	$26,%r8
	movl	%edx,-28(%rdi)
	shrq	$26,%r9

	movq	%rbx,%rax
	movq	%r12,%rdx
	shlq	$12,%rax
	shlq	$12,%rdx
	orq	%r8,%rax
	orq	%r9,%rdx
	andl	$0x3ffffff,%eax
	andl	$0x3ffffff,%edx
	movl	%eax,-16(%rdi)
	leal	(%rax,%rax,4),%eax
	movl	%edx,-12(%rdi)
	leal	(%rdx,%rdx,4),%edx
	movl	%eax,0(%rdi)
	movq	%rbx,%r8
	movl	%edx,4(%rdi)
	movq	%r12,%r9

	movl	$0x3ffffff,%eax
	movl	$0x3ffffff,%edx
	shrq	$14,%r8
	shrq	$14,%r9
	andl	%r8d,%eax
	andl	%r9d,%edx
	movl	%eax,16(%rdi)
	leal	(%rax,%rax,4),%eax
	movl	%edx,20(%rdi)
	leal	(%rdx,%rdx,4),%edx
	movl	%eax,32(%rdi)
	shrq	$26,%r8
	movl	%edx,36(%rdi)
	shrq	$26,%r9

	movq	%rbp,%rax
	shlq	$24,%rax
	orq	%rax,%r8
	movl	%r8d,48(%rdi)
	leaq	(%r8,%r8,4),%r8
	movl	%r9d,52(%rdi)
	leaq	(%r9,%r9,4),%r9
	movl	%r8d,64(%rdi)
	movl	%r9d,68(%rdi)

	movq	%r12,%rax
	call	__crypton_poly1305_asm_block

	movl	$0x3ffffff,%eax
	movq	%r14,%r8
	andl	%r14d,%eax
	shrq	$26,%r8
	movl	%eax,-52(%rdi)

	movl	$0x3ffffff,%edx
	andl	%r8d,%edx
	movl	%edx,-36(%rdi)
	leal	(%rdx,%rdx,4),%edx
	shrq	$26,%r8
	movl	%edx,-20(%rdi)

	movq	%rbx,%rax
	shlq	$12,%rax
	orq	%r8,%rax
	andl	$0x3ffffff,%eax
	movl	%eax,-4(%rdi)
	leal	(%rax,%rax,4),%eax
	movq	%rbx,%r8
	movl	%eax,12(%rdi)

	movl	$0x3ffffff,%edx
	shrq	$14,%r8
	andl	%r8d,%edx
	movl	%edx,28(%rdi)
	leal	(%rdx,%rdx,4),%edx
	shrq	$26,%r8
	movl	%edx,44(%rdi)

	movq	%rbp,%rax
	shlq	$24,%rax
	orq	%rax,%r8
	movl	%r8d,60(%rdi)
	leaq	(%r8,%r8,4),%r8
	movl	%r8d,76(%rdi)

	movq	%r12,%rax
	call	__crypton_poly1305_asm_block

	movl	$0x3ffffff,%eax
	movq	%r14,%r8
	andl	%r14d,%eax
	shrq	$26,%r8
	movl	%eax,-56(%rdi)

	movl	$0x3ffffff,%edx
	andl	%r8d,%edx
	movl	%edx,-40(%rdi)
	leal	(%rdx,%rdx,4),%edx
	shrq	$26,%r8
	movl	%edx,-24(%rdi)

	movq	%rbx,%rax
	shlq	$12,%rax
	orq	%r8,%rax
	andl	$0x3ffffff,%eax
	movl	%eax,-8(%rdi)
	leal	(%rax,%rax,4),%eax
	movq	%rbx,%r8
	movl	%eax,8(%rdi)

	movl	$0x3ffffff,%edx
	shrq	$14,%r8
	andl	%r8d,%edx
	movl	%edx,24(%rdi)
	leal	(%rdx,%rdx,4),%edx
	shrq	$26,%r8
	movl	%edx,40(%rdi)

	movq	%rbp,%rax
	shlq	$24,%rax
	orq	%rax,%r8
	movl	%r8d,56(%rdi)
	leaq	(%r8,%r8,4),%r8
	movl	%r8d,72(%rdi)

	leaq	-48-64(%rdi),%rdi
.Ldone_init_avx:
	.byte	0xf3,0xc3


.def	crypton_poly1305_asm_blocks_avx;	.scl 3;	.type 32;	.endef
.p2align	5
crypton_poly1305_asm_blocks_avx:
	.byte	0xf3,0x0f,0x1e,0xfa
	movq	%rdi,8(%rsp)
	movq	%rsi,16(%rsp)
	movq	%rsp,%rax
.LSEH_begin_crypton_poly1305_asm_blocks_avx:


	movq	%rcx,%rdi
	movq	%rdx,%rsi
	movq	%r8,%rdx
	movq	%r9,%rcx
	movl	20(%rdi),%r8d
	cmpq	$128,%rdx
	jb	.Lblocks

	andq	$-16,%rdx

	vzeroupper

	testl	%r8d,%r8d
	jz	.Lbase2_64_avx

	testq	$31,%rdx
	jz	.Leven_avx

	pushq	%rbx

	pushq	%rbp

	pushq	%r12

	pushq	%r13

	pushq	%r14

	pushq	%r15

	leaq	-8(%rsp),%rsp

.Lblocks_avx_body:

	movq	%rdx,%r15

	movq	0(%rdi),%r8
	movq	8(%rdi),%r9
	movl	16(%rdi),%ebp

	movq	24(%rdi),%r11
	movq	32(%rdi),%r13


	movl	%r8d,%r14d
	andq	$-2147483648,%r8
	movq	%r9,%r12
	movl	%r9d,%ebx
	andq	$-2147483648,%r9

	shrq	$6,%r8
	shlq	$52,%r12
	addq	%r8,%r14
	shrq	$12,%rbx
	shrq	$18,%r9
	addq	%r12,%r14
	adcq	%r9,%rbx

	movq	%rbp,%r8
	shlq	$40,%r8
	shrq	$24,%rbp
	addq	%r8,%rbx
	adcq	$0,%rbp

	movq	%r13,%r12
	movq	%r13,%rax
	shrq	$2,%r13
	addq	%r12,%r13

	addq	0(%rsi),%r14
	adcq	8(%rsi),%rbx
	leaq	16(%rsi),%rsi
	adcq	%rcx,%rbp

	call	__crypton_poly1305_asm_block


	movq	%r14,%rax
	movq	%r14,%rdx
	shrq	$52,%r14
	movq	%rbx,%r11
	movq	%rbx,%r12
	shrq	$26,%rdx
	andq	$0x3ffffff,%rax
	shlq	$12,%r11
	andq	$0x3ffffff,%rdx
	shrq	$14,%rbx
	orq	%r11,%r14
	shlq	$24,%rbp
	andq	$0x3ffffff,%r14
	shrq	$40,%r12
	andq	$0x3ffffff,%rbx
	orq	%r12,%rbp

	vmovd	%eax,%xmm0
	vmovd	%edx,%xmm1
	vmovd	%r14d,%xmm2
	vmovd	%ebx,%xmm3
	vmovd	%ebp,%xmm4

	leaq	-16(%r15),%rdx

	movq	8(%rsp),%r15

	movq	16(%rsp),%r14

	movq	24(%rsp),%r13

	movq	32(%rsp),%r12

	movq	40(%rsp),%rbp

	movq	48(%rsp),%rbx

	leaq	56(%rsp),%rax
	leaq	56(%rsp),%rsp

.Lblocks_avx_epilogue:
	jmp	.Ldo_avx


.p2align	5
.Lbase2_64_avx:

	pushq	%rbx

	pushq	%rbp

	pushq	%r12

	pushq	%r13

	pushq	%r14

	pushq	%r15

	leaq	-8(%rsp),%rsp

.Lbase2_64_avx_body:

	movq	%rdx,%r15

	movq	24(%rdi),%r11
	movq	32(%rdi),%r13

	movq	0(%rdi),%r14
	movq	8(%rdi),%rbx
	movl	16(%rdi),%ebp

	movq	%r13,%r12
	movq	%r13,%rax
	shrq	$2,%r13
	addq	%r12,%r13

	testq	$31,%rdx
	jz	.Linit_avx

	addq	0(%rsi),%r14
	adcq	8(%rsi),%rbx
	leaq	16(%rsi),%rsi
	adcq	%rcx,%rbp
	subq	$16,%r15

	call	__crypton_poly1305_asm_block

.Linit_avx:

	movq	%r14,%rax
	movq	%r14,%rdx
	shrq	$52,%r14
	movq	%rbx,%r8
	movq	%rbx,%r9
	shrq	$26,%rdx
	andq	$0x3ffffff,%rax
	shlq	$12,%r8
	andq	$0x3ffffff,%rdx
	shrq	$14,%rbx
	orq	%r8,%r14
	shlq	$24,%rbp
	andq	$0x3ffffff,%r14
	shrq	$40,%r9
	andq	$0x3ffffff,%rbx
	orq	%r9,%rbp

	vmovd	%eax,%xmm0
	vmovd	%edx,%xmm1
	vmovd	%r14d,%xmm2
	vmovd	%ebx,%xmm3
	vmovd	%ebp,%xmm4
	movl	$1,20(%rdi)

	call	__crypton_poly1305_asm_init_avx

	movq	%r15,%rdx

	movq	8(%rsp),%r15

	movq	16(%rsp),%r14

	movq	24(%rsp),%r13

	movq	32(%rsp),%r12

	movq	40(%rsp),%rbp

	movq	48(%rsp),%rbx

	leaq	56(%rsp),%rax
	leaq	56(%rsp),%rsp

.Lbase2_64_avx_epilogue:
	jmp	.Ldo_avx


.p2align	5
.Leven_avx:

	vmovd	0(%rdi),%xmm0
	vmovd	4(%rdi),%xmm1
	vmovd	8(%rdi),%xmm2
	vmovd	12(%rdi),%xmm3
	vmovd	16(%rdi),%xmm4

.Ldo_avx:
	leaq	-248(%rsp),%r11
	subq	$0x218,%rsp
	vmovdqa	%xmm6,80(%r11)
	vmovdqa	%xmm7,96(%r11)
	vmovdqa	%xmm8,112(%r11)
	vmovdqa	%xmm9,128(%r11)
	vmovdqa	%xmm10,144(%r11)
	vmovdqa	%xmm11,160(%r11)
	vmovdqa	%xmm12,176(%r11)
	vmovdqa	%xmm13,192(%r11)
	vmovdqa	%xmm14,208(%r11)
	vmovdqa	%xmm15,224(%r11)
.Ldo_avx_body:
	subq	$64,%rdx
	leaq	-32(%rsi),%rax
	cmovcq	%rax,%rsi

	vmovdqu	48(%rdi),%xmm14
	leaq	112(%rdi),%rdi
	leaq	.Lconst(%rip),%rcx



	vmovdqu	32(%rsi),%xmm5
	vmovdqu	48(%rsi),%xmm6
	vmovdqa	64(%rcx),%xmm15

	vpsrldq	$6,%xmm5,%xmm7
	vpsrldq	$6,%xmm6,%xmm8
	vpunpckhqdq	%xmm6,%xmm5,%xmm9
	vpunpcklqdq	%xmm6,%xmm5,%xmm5
	vpunpcklqdq	%xmm8,%xmm7,%xmm8

	vpsrlq	$40,%xmm9,%xmm9
	vpsrlq	$26,%xmm5,%xmm6
	vpand	%xmm15,%xmm5,%xmm5
	vpsrlq	$4,%xmm8,%xmm7
	vpand	%xmm15,%xmm6,%xmm6
	vpsrlq	$30,%xmm8,%xmm8
	vpand	%xmm15,%xmm7,%xmm7
	vpand	%xmm15,%xmm8,%xmm8
	vpor	32(%rcx),%xmm9,%xmm9

	jbe	.Lskip_loop_avx


	vmovdqu	-48(%rdi),%xmm11
	vmovdqu	-32(%rdi),%xmm12
	vpshufd	$0xEE,%xmm14,%xmm13
	vpshufd	$0x44,%xmm14,%xmm10
	vmovdqa	%xmm13,-144(%r11)
	vmovdqa	%xmm10,0(%rsp)
	vpshufd	$0xEE,%xmm11,%xmm14
	vmovdqu	-16(%rdi),%xmm10
	vpshufd	$0x44,%xmm11,%xmm11
	vmovdqa	%xmm14,-128(%r11)
	vmovdqa	%xmm11,16(%rsp)
	vpshufd	$0xEE,%xmm12,%xmm13
	vmovdqu	0(%rdi),%xmm11
	vpshufd	$0x44,%xmm12,%xmm12
	vmovdqa	%xmm13,-112(%r11)
	vmovdqa	%xmm12,32(%rsp)
	vpshufd	$0xEE,%xmm10,%xmm14
	vmovdqu	16(%rdi),%xmm12
	vpshufd	$0x44,%xmm10,%xmm10
	vmovdqa	%xmm14,-96(%r11)
	vmovdqa	%xmm10,48(%rsp)
	vpshufd	$0xEE,%xmm11,%xmm13
	vmovdqu	32(%rdi),%xmm10
	vpshufd	$0x44,%xmm11,%xmm11
	vmovdqa	%xmm13,-80(%r11)
	vmovdqa	%xmm11,64(%rsp)
	vpshufd	$0xEE,%xmm12,%xmm14
	vmovdqu	48(%rdi),%xmm11
	vpshufd	$0x44,%xmm12,%xmm12
	vmovdqa	%xmm14,-64(%r11)
	vmovdqa	%xmm12,80(%rsp)
	vpshufd	$0xEE,%xmm10,%xmm13
	vmovdqu	64(%rdi),%xmm12
	vpshufd	$0x44,%xmm10,%xmm10
	vmovdqa	%xmm13,-48(%r11)
	vmovdqa	%xmm10,96(%rsp)
	vpshufd	$0xEE,%xmm11,%xmm14
	vpshufd	$0x44,%xmm11,%xmm11
	vmovdqa	%xmm14,-32(%r11)
	vmovdqa	%xmm11,112(%rsp)
	vpshufd	$0xEE,%xmm12,%xmm13
	vmovdqa	0(%rsp),%xmm14
	vpshufd	$0x44,%xmm12,%xmm12
	vmovdqa	%xmm13,-16(%r11)
	vmovdqa	%xmm12,128(%rsp)

	jmp	.Loop_avx

.p2align	5
.Loop_avx:




















	vpmuludq	%xmm5,%xmm14,%xmm10
	vpmuludq	%xmm6,%xmm14,%xmm11
	vmovdqa	%xmm2,32(%r11)
	vpmuludq	%xmm7,%xmm14,%xmm12
	vmovdqa	16(%rsp),%xmm2
	vpmuludq	%xmm8,%xmm14,%xmm13
	vpmuludq	%xmm9,%xmm14,%xmm14

	vmovdqa	%xmm0,0(%r11)
	vpmuludq	32(%rsp),%xmm9,%xmm0
	vmovdqa	%xmm1,16(%r11)
	vpmuludq	%xmm8,%xmm2,%xmm1
	vpaddq	%xmm0,%xmm10,%xmm10
	vpaddq	%xmm1,%xmm14,%xmm14
	vmovdqa	%xmm3,48(%r11)
	vpmuludq	%xmm7,%xmm2,%xmm0
	vpmuludq	%xmm6,%xmm2,%xmm1
	vpaddq	%xmm0,%xmm13,%xmm13
	vmovdqa	48(%rsp),%xmm3
	vpaddq	%xmm1,%xmm12,%xmm12
	vmovdqa	%xmm4,64(%r11)
	vpmuludq	%xmm5,%xmm2,%xmm2
	vpmuludq	%xmm7,%xmm3,%xmm0
	vpaddq	%xmm2,%xmm11,%xmm11

	vmovdqa	64(%rsp),%xmm4
	vpaddq	%xmm0,%xmm14,%xmm14
	vpmuludq	%xmm6,%xmm3,%xmm1
	vpmuludq	%xmm5,%xmm3,%xmm3
	vpaddq	%xmm1,%xmm13,%xmm13
	vmovdqa	80(%rsp),%xmm2
	vpaddq	%xmm3,%xmm12,%xmm12
	vpmuludq	%xmm9,%xmm4,%xmm0
	vpmuludq	%xmm8,%xmm4,%xmm4
	vpaddq	%xmm0,%xmm11,%xmm11
	vmovdqa	96(%rsp),%xmm3
	vpaddq	%xmm4,%xmm10,%xmm10

	vmovdqa	128(%rsp),%xmm4
	vpmuludq	%xmm6,%xmm2,%xmm1
	vpmuludq	%xmm5,%xmm2,%xmm2
	vpaddq	%xmm1,%xmm14,%xmm14
	vpaddq	%xmm2,%xmm13,%xmm13
	vpmuludq	%xmm9,%xmm3,%xmm0
	vpmuludq	%xmm8,%xmm3,%xmm1
	vpaddq	%xmm0,%xmm12,%xmm12
	vmovdqu	0(%rsi),%xmm0
	vpaddq	%xmm1,%xmm11,%xmm11
	vpmuludq	%xmm7,%xmm3,%xmm3
	vpmuludq	%xmm7,%xmm4,%xmm7
	vpaddq	%xmm3,%xmm10,%xmm10

	vmovdqu	16(%rsi),%xmm1
	vpaddq	%xmm7,%xmm11,%xmm11
	vpmuludq	%xmm8,%xmm4,%xmm8
	vpmuludq	%xmm9,%xmm4,%xmm9
	vpsrldq	$6,%xmm0,%xmm2
	vpaddq	%xmm8,%xmm12,%xmm12
	vpaddq	%xmm9,%xmm13,%xmm13
	vpsrldq	$6,%xmm1,%xmm3
	vpmuludq	112(%rsp),%xmm5,%xmm9
	vpmuludq	%xmm6,%xmm4,%xmm5
	vpunpckhqdq	%xmm1,%xmm0,%xmm4
	vpaddq	%xmm9,%xmm14,%xmm14
	vmovdqa	-144(%r11),%xmm9
	vpaddq	%xmm5,%xmm10,%xmm10

	vpunpcklqdq	%xmm1,%xmm0,%xmm0
	vpunpcklqdq	%xmm3,%xmm2,%xmm3


	vpsrldq	$5,%xmm4,%xmm4
	vpsrlq	$26,%xmm0,%xmm1
	vpand	%xmm15,%xmm0,%xmm0
	vpsrlq	$4,%xmm3,%xmm2
	vpand	%xmm15,%xmm1,%xmm1
	vpand	0(%rcx),%xmm4,%xmm4
	vpsrlq	$30,%xmm3,%xmm3
	vpand	%xmm15,%xmm2,%xmm2
	vpand	%xmm15,%xmm3,%xmm3
	vpor	32(%rcx),%xmm4,%xmm4

	vpaddq	0(%r11),%xmm0,%xmm0
	vpaddq	16(%r11),%xmm1,%xmm1
	vpaddq	32(%r11),%xmm2,%xmm2
	vpaddq	48(%r11),%xmm3,%xmm3
	vpaddq	64(%r11),%xmm4,%xmm4

	leaq	32(%rsi),%rax
	leaq	64(%rsi),%rsi
	subq	$64,%rdx
	cmovcq	%rax,%rsi










	vpmuludq	%xmm0,%xmm9,%xmm5
	vpmuludq	%xmm1,%xmm9,%xmm6
	vpaddq	%xmm5,%xmm10,%xmm10
	vpaddq	%xmm6,%xmm11,%xmm11
	vmovdqa	-128(%r11),%xmm7
	vpmuludq	%xmm2,%xmm9,%xmm5
	vpmuludq	%xmm3,%xmm9,%xmm6
	vpaddq	%xmm5,%xmm12,%xmm12
	vpaddq	%xmm6,%xmm13,%xmm13
	vpmuludq	%xmm4,%xmm9,%xmm9
	vpmuludq	-112(%r11),%xmm4,%xmm5
	vpaddq	%xmm9,%xmm14,%xmm14

	vpaddq	%xmm5,%xmm10,%xmm10
	vpmuludq	%xmm2,%xmm7,%xmm6
	vpmuludq	%xmm3,%xmm7,%xmm5
	vpaddq	%xmm6,%xmm13,%xmm13
	vmovdqa	-96(%r11),%xmm8
	vpaddq	%xmm5,%xmm14,%xmm14
	vpmuludq	%xmm1,%xmm7,%xmm6
	vpmuludq	%xmm0,%xmm7,%xmm7
	vpaddq	%xmm6,%xmm12,%xmm12
	vpaddq	%xmm7,%xmm11,%xmm11

	vmovdqa	-80(%r11),%xmm9
	vpmuludq	%xmm2,%xmm8,%xmm5
	vpmuludq	%xmm1,%xmm8,%xmm6
	vpaddq	%xmm5,%xmm14,%xmm14
	vpaddq	%xmm6,%xmm13,%xmm13
	vmovdqa	-64(%r11),%xmm7
	vpmuludq	%xmm0,%xmm8,%xmm8
	vpmuludq	%xmm4,%xmm9,%xmm5
	vpaddq	%xmm8,%xmm12,%xmm12
	vpaddq	%xmm5,%xmm11,%xmm11
	vmovdqa	-48(%r11),%xmm8
	vpmuludq	%xmm3,%xmm9,%xmm9
	vpmuludq	%xmm1,%xmm7,%xmm6
	vpaddq	%xmm9,%xmm10,%xmm10

	vmovdqa	-16(%r11),%xmm9
	vpaddq	%xmm6,%xmm14,%xmm14
	vpmuludq	%xmm0,%xmm7,%xmm7
	vpmuludq	%xmm4,%xmm8,%xmm5
	vpaddq	%xmm7,%xmm13,%xmm13
	vpaddq	%xmm5,%xmm12,%xmm12
	vmovdqu	32(%rsi),%xmm5
	vpmuludq	%xmm3,%xmm8,%xmm7
	vpmuludq	%xmm2,%xmm8,%xmm8
	vpaddq	%xmm7,%xmm11,%xmm11
	vmovdqu	48(%rsi),%xmm6
	vpaddq	%xmm8,%xmm10,%xmm10

	vpmuludq	%xmm2,%xmm9,%xmm2
	vpmuludq	%xmm3,%xmm9,%xmm3
	vpsrldq	$6,%xmm5,%xmm7
	vpaddq	%xmm2,%xmm11,%xmm11
	vpmuludq	%xmm4,%xmm9,%xmm4
	vpsrldq	$6,%xmm6,%xmm8
	vpaddq	%xmm3,%xmm12,%xmm2
	vpaddq	%xmm4,%xmm13,%xmm3
	vpmuludq	-32(%r11),%xmm0,%xmm4
	vpmuludq	%xmm1,%xmm9,%xmm0
	vpunpckhqdq	%xmm6,%xmm5,%xmm9
	vpaddq	%xmm4,%xmm14,%xmm4
	vpaddq	%xmm0,%xmm10,%xmm0

	vpunpcklqdq	%xmm6,%xmm5,%xmm5
	vpunpcklqdq	%xmm8,%xmm7,%xmm8


	vpsrldq	$5,%xmm9,%xmm9
	vpsrlq	$26,%xmm5,%xmm6
	vmovdqa	0(%rsp),%xmm14
	vpand	%xmm15,%xmm5,%xmm5
	vpsrlq	$4,%xmm8,%xmm7
	vpand	%xmm15,%xmm6,%xmm6
	vpand	0(%rcx),%xmm9,%xmm9
	vpsrlq	$30,%xmm8,%xmm8
	vpand	%xmm15,%xmm7,%xmm7
	vpand	%xmm15,%xmm8,%xmm8
	vpor	32(%rcx),%xmm9,%xmm9





	vpsrlq	$26,%xmm3,%xmm13
	vpand	%xmm15,%xmm3,%xmm3
	vpaddq	%xmm13,%xmm4,%xmm4

	vpsrlq	$26,%xmm0,%xmm10
	vpand	%xmm15,%xmm0,%xmm0
	vpaddq	%xmm10,%xmm11,%xmm1

	vpsrlq	$26,%xmm4,%xmm10
	vpand	%xmm15,%xmm4,%xmm4

	vpsrlq	$26,%xmm1,%xmm11
	vpand	%xmm15,%xmm1,%xmm1
	vpaddq	%xmm11,%xmm2,%xmm2

	vpaddq	%xmm10,%xmm0,%xmm0
	vpsllq	$2,%xmm10,%xmm10
	vpaddq	%xmm10,%xmm0,%xmm0

	vpsrlq	$26,%xmm2,%xmm12
	vpand	%xmm15,%xmm2,%xmm2
	vpaddq	%xmm12,%xmm3,%xmm3

	vpsrlq	$26,%xmm0,%xmm10
	vpand	%xmm15,%xmm0,%xmm0
	vpaddq	%xmm10,%xmm1,%xmm1

	vpsrlq	$26,%xmm3,%xmm13
	vpand	%xmm15,%xmm3,%xmm3
	vpaddq	%xmm13,%xmm4,%xmm4

	ja	.Loop_avx

.Lskip_loop_avx:



	vpshufd	$0x10,%xmm14,%xmm14
	addq	$32,%rdx
	jnz	.Long_tail_avx

	vpaddq	%xmm2,%xmm7,%xmm7
	vpaddq	%xmm0,%xmm5,%xmm5
	vpaddq	%xmm1,%xmm6,%xmm6
	vpaddq	%xmm3,%xmm8,%xmm8
	vpaddq	%xmm4,%xmm9,%xmm9

.Long_tail_avx:
	vmovdqa	%xmm2,32(%r11)
	vmovdqa	%xmm0,0(%r11)
	vmovdqa	%xmm1,16(%r11)
	vmovdqa	%xmm3,48(%r11)
	vmovdqa	%xmm4,64(%r11)







	vpmuludq	%xmm7,%xmm14,%xmm12
	vpmuludq	%xmm5,%xmm14,%xmm10
	vpshufd	$0x10,-48(%rdi),%xmm2
	vpmuludq	%xmm6,%xmm14,%xmm11
	vpmuludq	%xmm8,%xmm14,%xmm13
	vpmuludq	%xmm9,%xmm14,%xmm14

	vpmuludq	%xmm8,%xmm2,%xmm0
	vpaddq	%xmm0,%xmm14,%xmm14
	vpshufd	$0x10,-32(%rdi),%xmm3
	vpmuludq	%xmm7,%xmm2,%xmm1
	vpaddq	%xmm1,%xmm13,%xmm13
	vpshufd	$0x10,-16(%rdi),%xmm4
	vpmuludq	%xmm6,%xmm2,%xmm0
	vpaddq	%xmm0,%xmm12,%xmm12
	vpmuludq	%xmm5,%xmm2,%xmm2
	vpaddq	%xmm2,%xmm11,%xmm11
	vpmuludq	%xmm9,%xmm3,%xmm3
	vpaddq	%xmm3,%xmm10,%xmm10

	vpshufd	$0x10,0(%rdi),%xmm2
	vpmuludq	%xmm7,%xmm4,%xmm1
	vpaddq	%xmm1,%xmm14,%xmm14
	vpmuludq	%xmm6,%xmm4,%xmm0
	vpaddq	%xmm0,%xmm13,%xmm13
	vpshufd	$0x10,16(%rdi),%xmm3
	vpmuludq	%xmm5,%xmm4,%xmm4
	vpaddq	%xmm4,%xmm12,%xmm12
	vpmuludq	%xmm9,%xmm2,%xmm1
	vpaddq	%xmm1,%xmm11,%xmm11
	vpshufd	$0x10,32(%rdi),%xmm4
	vpmuludq	%xmm8,%xmm2,%xmm2
	vpaddq	%xmm2,%xmm10,%xmm10

	vpmuludq	%xmm6,%xmm3,%xmm0
	vpaddq	%xmm0,%xmm14,%xmm14
	vpmuludq	%xmm5,%xmm3,%xmm3
	vpaddq	%xmm3,%xmm13,%xmm13
	vpshufd	$0x10,48(%rdi),%xmm2
	vpmuludq	%xmm9,%xmm4,%xmm1
	vpaddq	%xmm1,%xmm12,%xmm12
	vpshufd	$0x10,64(%rdi),%xmm3
	vpmuludq	%xmm8,%xmm4,%xmm0
	vpaddq	%xmm0,%xmm11,%xmm11
	vpmuludq	%xmm7,%xmm4,%xmm4
	vpaddq	%xmm4,%xmm10,%xmm10

	vpmuludq	%xmm5,%xmm2,%xmm2
	vpaddq	%xmm2,%xmm14,%xmm14
	vpmuludq	%xmm9,%xmm3,%xmm1
	vpaddq	%xmm1,%xmm13,%xmm13
	vpmuludq	%xmm8,%xmm3,%xmm0
	vpaddq	%xmm0,%xmm12,%xmm12
	vpmuludq	%xmm7,%xmm3,%xmm1
	vpaddq	%xmm1,%xmm11,%xmm11
	vpmuludq	%xmm6,%xmm3,%xmm3
	vpaddq	%xmm3,%xmm10,%xmm10

	jz	.Lshort_tail_avx

	vmovdqu	0(%rsi),%xmm0
	vmovdqu	16(%rsi),%xmm1

	vpsrldq	$6,%xmm0,%xmm2
	vpsrldq	$6,%xmm1,%xmm3
	vpunpckhqdq	%xmm1,%xmm0,%xmm4
	vpunpcklqdq	%xmm1,%xmm0,%xmm0
	vpunpcklqdq	%xmm3,%xmm2,%xmm3

	vpsrlq	$40,%xmm4,%xmm4
	vpsrlq	$26,%xmm0,%xmm1
	vpand	%xmm15,%xmm0,%xmm0
	vpsrlq	$4,%xmm3,%xmm2
	vpand	%xmm15,%xmm1,%xmm1
	vpsrlq	$30,%xmm3,%xmm3
	vpand	%xmm15,%xmm2,%xmm2
	vpand	%xmm15,%xmm3,%xmm3
	vpor	32(%rcx),%xmm4,%xmm4

	vpshufd	$0x32,-64(%rdi),%xmm9
	vpaddq	0(%r11),%xmm0,%xmm0
	vpaddq	16(%r11),%xmm1,%xmm1
	vpaddq	32(%r11),%xmm2,%xmm2
	vpaddq	48(%r11),%xmm3,%xmm3
	vpaddq	64(%r11),%xmm4,%xmm4




	vpmuludq	%xmm0,%xmm9,%xmm5
	vpaddq	%xmm5,%xmm10,%xmm10
	vpmuludq	%xmm1,%xmm9,%xmm6
	vpaddq	%xmm6,%xmm11,%xmm11
	vpmuludq	%xmm2,%xmm9,%xmm5
	vpaddq	%xmm5,%xmm12,%xmm12
	vpshufd	$0x32,-48(%rdi),%xmm7
	vpmuludq	%xmm3,%xmm9,%xmm6
	vpaddq	%xmm6,%xmm13,%xmm13
	vpmuludq	%xmm4,%xmm9,%xmm9
	vpaddq	%xmm9,%xmm14,%xmm14

	vpmuludq	%xmm3,%xmm7,%xmm5
	vpaddq	%xmm5,%xmm14,%xmm14
	vpshufd	$0x32,-32(%rdi),%xmm8
	vpmuludq	%xmm2,%xmm7,%xmm6
	vpaddq	%xmm6,%xmm13,%xmm13
	vpshufd	$0x32,-16(%rdi),%xmm9
	vpmuludq	%xmm1,%xmm7,%xmm5
	vpaddq	%xmm5,%xmm12,%xmm12
	vpmuludq	%xmm0,%xmm7,%xmm7
	vpaddq	%xmm7,%xmm11,%xmm11
	vpmuludq	%xmm4,%xmm8,%xmm8
	vpaddq	%xmm8,%xmm10,%xmm10

	vpshufd	$0x32,0(%rdi),%xmm7
	vpmuludq	%xmm2,%xmm9,%xmm6
	vpaddq	%xmm6,%xmm14,%xmm14
	vpmuludq	%xmm1,%xmm9,%xmm5
	vpaddq	%xmm5,%xmm13,%xmm13
	vpshufd	$0x32,16(%rdi),%xmm8
	vpmuludq	%xmm0,%xmm9,%xmm9
	vpaddq	%xmm9,%xmm12,%xmm12
	vpmuludq	%xmm4,%xmm7,%xmm6
	vpaddq	%xmm6,%xmm11,%xmm11
	vpshufd	$0x32,32(%rdi),%xmm9
	vpmuludq	%xmm3,%xmm7,%xmm7
	vpaddq	%xmm7,%xmm10,%xmm10

	vpmuludq	%xmm1,%xmm8,%xmm5
	vpaddq	%xmm5,%xmm14,%xmm14
	vpmuludq	%xmm0,%xmm8,%xmm8
	vpaddq	%xmm8,%xmm13,%xmm13
	vpshufd	$0x32,48(%rdi),%xmm7
	vpmuludq	%xmm4,%xmm9,%xmm6
	vpaddq	%xmm6,%xmm12,%xmm12
	vpshufd	$0x32,64(%rdi),%xmm8
	vpmuludq	%xmm3,%xmm9,%xmm5
	vpaddq	%xmm5,%xmm11,%xmm11
	vpmuludq	%xmm2,%xmm9,%xmm9
	vpaddq	%xmm9,%xmm10,%xmm10

	vpmuludq	%xmm0,%xmm7,%xmm7
	vpaddq	%xmm7,%xmm14,%xmm14
	vpmuludq	%xmm4,%xmm8,%xmm6
	vpaddq	%xmm6,%xmm13,%xmm13
	vpmuludq	%xmm3,%xmm8,%xmm5
	vpaddq	%xmm5,%xmm12,%xmm12
	vpmuludq	%xmm2,%xmm8,%xmm6
	vpaddq	%xmm6,%xmm11,%xmm11
	vpmuludq	%xmm1,%xmm8,%xmm8
	vpaddq	%xmm8,%xmm10,%xmm10

.Lshort_tail_avx:



	vpsrldq	$8,%xmm14,%xmm9
	vpsrldq	$8,%xmm13,%xmm8
	vpsrldq	$8,%xmm11,%xmm6
	vpsrldq	$8,%xmm10,%xmm5
	vpsrldq	$8,%xmm12,%xmm7
	vpaddq	%xmm8,%xmm13,%xmm13
	vpaddq	%xmm9,%xmm14,%xmm14
	vpaddq	%xmm5,%xmm10,%xmm10
	vpaddq	%xmm6,%xmm11,%xmm11
	vpaddq	%xmm7,%xmm12,%xmm12




	vpsrlq	$26,%xmm13,%xmm3
	vpand	%xmm15,%xmm13,%xmm13
	vpaddq	%xmm3,%xmm14,%xmm14

	vpsrlq	$26,%xmm10,%xmm0
	vpand	%xmm15,%xmm10,%xmm10
	vpaddq	%xmm0,%xmm11,%xmm11

	vpsrlq	$26,%xmm14,%xmm4
	vpand	%xmm15,%xmm14,%xmm14

	vpsrlq	$26,%xmm11,%xmm1
	vpand	%xmm15,%xmm11,%xmm11
	vpaddq	%xmm1,%xmm12,%xmm12

	vpaddq	%xmm4,%xmm10,%xmm10
	vpsllq	$2,%xmm4,%xmm4
	vpaddq	%xmm4,%xmm10,%xmm10

	vpsrlq	$26,%xmm12,%xmm2
	vpand	%xmm15,%xmm12,%xmm12
	vpaddq	%xmm2,%xmm13,%xmm13

	vpsrlq	$26,%xmm10,%xmm0
	vpand	%xmm15,%xmm10,%xmm10
	vpaddq	%xmm0,%xmm11,%xmm11

	vpsrlq	$26,%xmm13,%xmm3
	vpand	%xmm15,%xmm13,%xmm13
	vpaddq	%xmm3,%xmm14,%xmm14

	vmovd	%xmm10,-112(%rdi)
	vmovd	%xmm11,-108(%rdi)
	vmovd	%xmm12,-104(%rdi)
	vmovd	%xmm13,-100(%rdi)
	vmovd	%xmm14,-96(%rdi)
	vmovdqa	80(%r11),%xmm6
	vmovdqa	96(%r11),%xmm7
	vmovdqa	112(%r11),%xmm8
	vmovdqa	128(%r11),%xmm9
	vmovdqa	144(%r11),%xmm10
	vmovdqa	160(%r11),%xmm11
	vmovdqa	176(%r11),%xmm12
	vmovdqa	192(%r11),%xmm13
	vmovdqa	208(%r11),%xmm14
	vmovdqa	224(%r11),%xmm15
	leaq	248(%r11),%rsp
.Ldo_avx_epilogue:
	vzeroupper
	movq	8(%rsp),%rdi
	movq	16(%rsp),%rsi
	.byte	0xf3,0xc3

.LSEH_end_crypton_poly1305_asm_blocks_avx:
.def	crypton_poly1305_asm_blocks_avx2;	.scl 3;	.type 32;	.endef
.p2align	5
crypton_poly1305_asm_blocks_avx2:
	.byte	0xf3,0x0f,0x1e,0xfa
	movq	%rdi,8(%rsp)
	movq	%rsi,16(%rsp)
	movq	%rsp,%rax
.LSEH_begin_crypton_poly1305_asm_blocks_avx2:


	movq	%rcx,%rdi
	movq	%rdx,%rsi
	movq	%r8,%rdx
	movq	%r9,%rcx
	movl	20(%rdi),%r8d
	cmpq	$128,%rdx
	jb	.Lblocks

	andq	$-16,%rdx

	vzeroupper

	testl	%r8d,%r8d
	jz	.Lbase2_64_avx2

	testq	$63,%rdx
	jz	.Leven_avx2

	pushq	%rbx

	pushq	%rbp

	pushq	%r12

	pushq	%r13

	pushq	%r14

	pushq	%r15

	leaq	-8(%rsp),%rsp

.Lblocks_avx2_body:

	movq	%rdx,%r15

	movq	0(%rdi),%r8
	movq	8(%rdi),%r9
	movl	16(%rdi),%ebp

	movq	24(%rdi),%r11
	movq	32(%rdi),%r13


	movl	%r8d,%r14d
	andq	$-2147483648,%r8
	movq	%r9,%r12
	movl	%r9d,%ebx
	andq	$-2147483648,%r9

	shrq	$6,%r8
	shlq	$52,%r12
	addq	%r8,%r14
	shrq	$12,%rbx
	shrq	$18,%r9
	addq	%r12,%r14
	adcq	%r9,%rbx

	movq	%rbp,%r8
	shlq	$40,%r8
	shrq	$24,%rbp
	addq	%r8,%rbx
	adcq	$0,%rbp

	movq	%r13,%r12
	movq	%r13,%rax
	shrq	$2,%r13
	addq	%r12,%r13

.Lbase2_26_pre_avx2:
	addq	0(%rsi),%r14
	adcq	8(%rsi),%rbx
	leaq	16(%rsi),%rsi
	adcq	%rcx,%rbp
	subq	$16,%r15

	call	__crypton_poly1305_asm_block
	movq	%r12,%rax

	testq	$63,%r15
	jnz	.Lbase2_26_pre_avx2


	movq	%r14,%rax
	movq	%r14,%rdx
	shrq	$52,%r14
	movq	%rbx,%r11
	movq	%rbx,%r12
	shrq	$26,%rdx
	andq	$0x3ffffff,%rax
	shlq	$12,%r11
	andq	$0x3ffffff,%rdx
	shrq	$14,%rbx
	orq	%r11,%r14
	shlq	$24,%rbp
	andq	$0x3ffffff,%r14
	shrq	$40,%r12
	andq	$0x3ffffff,%rbx
	orq	%r12,%rbp

	vmovd	%eax,%xmm0
	vmovd	%edx,%xmm1
	vmovd	%r14d,%xmm2
	vmovd	%ebx,%xmm3
	vmovd	%ebp,%xmm4

	movq	%r15,%rdx

	movq	8(%rsp),%r15

	movq	16(%rsp),%r14

	movq	24(%rsp),%r13

	movq	32(%rsp),%r12

	movq	40(%rsp),%rbp

	movq	48(%rsp),%rbx

	leaq	56(%rsp),%rax
	leaq	56(%rsp),%rsp

.Lblocks_avx2_epilogue:
	jmp	.Ldo_avx2


.p2align	5
.Lbase2_64_avx2:

	pushq	%rbx

	pushq	%rbp

	pushq	%r12

	pushq	%r13

	pushq	%r14

	pushq	%r15

	leaq	-8(%rsp),%rsp

.Lbase2_64_avx2_body:

	movq	%rdx,%r15

	movq	24(%rdi),%r11
	movq	32(%rdi),%r13

	movq	0(%rdi),%r14
	movq	8(%rdi),%rbx
	movl	16(%rdi),%ebp

	movq	%r13,%r12
	movq	%r13,%rax
	shrq	$2,%r13
	addq	%r12,%r13

	testq	$63,%rdx
	jz	.Linit_avx2

.Lbase2_64_pre_avx2:
	addq	0(%rsi),%r14
	adcq	8(%rsi),%rbx
	leaq	16(%rsi),%rsi
	adcq	%rcx,%rbp
	subq	$16,%r15

	call	__crypton_poly1305_asm_block
	movq	%r12,%rax

	testq	$63,%r15
	jnz	.Lbase2_64_pre_avx2

.Linit_avx2:

	movq	%r14,%rax
	movq	%r14,%rdx
	shrq	$52,%r14
	movq	%rbx,%r8
	movq	%rbx,%r9
	shrq	$26,%rdx
	andq	$0x3ffffff,%rax
	shlq	$12,%r8
	andq	$0x3ffffff,%rdx
	shrq	$14,%rbx
	orq	%r8,%r14
	shlq	$24,%rbp
	andq	$0x3ffffff,%r14
	shrq	$40,%r9
	andq	$0x3ffffff,%rbx
	orq	%r9,%rbp

	vmovd	%eax,%xmm0
	vmovd	%edx,%xmm1
	vmovd	%r14d,%xmm2
	vmovd	%ebx,%xmm3
	vmovd	%ebp,%xmm4
	movl	$1,20(%rdi)

	call	__crypton_poly1305_asm_init_avx

	movq	%r15,%rdx

	movq	8(%rsp),%r15

	movq	16(%rsp),%r14

	movq	24(%rsp),%r13

	movq	32(%rsp),%r12

	movq	40(%rsp),%rbp

	movq	48(%rsp),%rbx

	leaq	56(%rsp),%rax
	leaq	56(%rsp),%rsp

.Lbase2_64_avx2_epilogue:
	jmp	.Ldo_avx2


.p2align	5
.Leven_avx2:

	vmovd	0(%rdi),%xmm0
	vmovd	4(%rdi),%xmm1
	vmovd	8(%rdi),%xmm2
	vmovd	12(%rdi),%xmm3
	vmovd	16(%rdi),%xmm4

.Ldo_avx2:
	leaq	-248(%rsp),%r11
	subq	$0x1c8,%rsp
	vmovdqa	%xmm6,80(%r11)
	vmovdqa	%xmm7,96(%r11)
	vmovdqa	%xmm8,112(%r11)
	vmovdqa	%xmm9,128(%r11)
	vmovdqa	%xmm10,144(%r11)
	vmovdqa	%xmm11,160(%r11)
	vmovdqa	%xmm12,176(%r11)
	vmovdqa	%xmm13,192(%r11)
	vmovdqa	%xmm14,208(%r11)
	vmovdqa	%xmm15,224(%r11)
.Ldo_avx2_body:
	leaq	.Lconst(%rip),%rcx
	leaq	48+64(%rdi),%rdi
	vmovdqa	96(%rcx),%ymm7


	vmovdqu	-64(%rdi),%xmm9
	andq	$-512,%rsp
	vmovdqu	-48(%rdi),%xmm10
	vmovdqu	-32(%rdi),%xmm6
	vmovdqu	-16(%rdi),%xmm11
	vmovdqu	0(%rdi),%xmm12
	vmovdqu	16(%rdi),%xmm13
	leaq	144(%rsp),%rax
	vmovdqu	32(%rdi),%xmm14
	vpermd	%ymm9,%ymm7,%ymm9
	vmovdqu	48(%rdi),%xmm15
	vpermd	%ymm10,%ymm7,%ymm10
	vmovdqu	64(%rdi),%xmm5
	vpermd	%ymm6,%ymm7,%ymm6
	vmovdqa	%ymm9,0(%rsp)
	vpermd	%ymm11,%ymm7,%ymm11
	vmovdqa	%ymm10,32-144(%rax)
	vpermd	%ymm12,%ymm7,%ymm12
	vmovdqa	%ymm6,64-144(%rax)
	vpermd	%ymm13,%ymm7,%ymm13
	vmovdqa	%ymm11,96-144(%rax)
	vpermd	%ymm14,%ymm7,%ymm14
	vmovdqa	%ymm12,128-144(%rax)
	vpermd	%ymm15,%ymm7,%ymm15
	vmovdqa	%ymm13,160-144(%rax)
	vpermd	%ymm5,%ymm7,%ymm5
	vmovdqa	%ymm14,192-144(%rax)
	vmovdqa	%ymm15,224-144(%rax)
	vmovdqa	%ymm5,256-144(%rax)
	vmovdqa	64(%rcx),%ymm5



	vmovdqu	0(%rsi),%xmm7
	vmovdqu	16(%rsi),%xmm8
	vinserti128	$1,32(%rsi),%ymm7,%ymm7
	vinserti128	$1,48(%rsi),%ymm8,%ymm8
	leaq	64(%rsi),%rsi

	vpsrldq	$6,%ymm7,%ymm9
	vpsrldq	$6,%ymm8,%ymm10
	vpunpckhqdq	%ymm8,%ymm7,%ymm6
	vpunpcklqdq	%ymm10,%ymm9,%ymm9
	vpunpcklqdq	%ymm8,%ymm7,%ymm7

	vpsrlq	$30,%ymm9,%ymm10
	vpsrlq	$4,%ymm9,%ymm9
	vpsrlq	$26,%ymm7,%ymm8
	vpsrlq	$40,%ymm6,%ymm6
	vpand	%ymm5,%ymm9,%ymm9
	vpand	%ymm5,%ymm7,%ymm7
	vpand	%ymm5,%ymm8,%ymm8
	vpand	%ymm5,%ymm10,%ymm10
	vpor	32(%rcx),%ymm6,%ymm6

	vpaddq	%ymm2,%ymm9,%ymm2
	subq	$64,%rdx
	jz	.Ltail_avx2
	jmp	.Loop_avx2

.p2align	5
.Loop_avx2:








	vpaddq	%ymm0,%ymm7,%ymm0
	vmovdqa	0(%rsp),%ymm7
	vpaddq	%ymm1,%ymm8,%ymm1
	vmovdqa	32(%rsp),%ymm8
	vpaddq	%ymm3,%ymm10,%ymm3
	vmovdqa	96(%rsp),%ymm9
	vpaddq	%ymm4,%ymm6,%ymm4
	vmovdqa	48(%rax),%ymm10
	vmovdqa	112(%rax),%ymm5
















	vpmuludq	%ymm2,%ymm7,%ymm13
	vpmuludq	%ymm2,%ymm8,%ymm14
	vpmuludq	%ymm2,%ymm9,%ymm15
	vpmuludq	%ymm2,%ymm10,%ymm11
	vpmuludq	%ymm2,%ymm5,%ymm12

	vpmuludq	%ymm0,%ymm8,%ymm6
	vpmuludq	%ymm1,%ymm8,%ymm2
	vpaddq	%ymm6,%ymm12,%ymm12
	vpaddq	%ymm2,%ymm13,%ymm13
	vpmuludq	%ymm3,%ymm8,%ymm6
	vpmuludq	64(%rsp),%ymm4,%ymm2
	vpaddq	%ymm6,%ymm15,%ymm15
	vpaddq	%ymm2,%ymm11,%ymm11
	vmovdqa	-16(%rax),%ymm8

	vpmuludq	%ymm0,%ymm7,%ymm6
	vpmuludq	%ymm1,%ymm7,%ymm2
	vpaddq	%ymm6,%ymm11,%ymm11
	vpaddq	%ymm2,%ymm12,%ymm12
	vpmuludq	%ymm3,%ymm7,%ymm6
	vpmuludq	%ymm4,%ymm7,%ymm2
	vmovdqu	0(%rsi),%xmm7
	vpaddq	%ymm6,%ymm14,%ymm14
	vpaddq	%ymm2,%ymm15,%ymm15
	vinserti128	$1,32(%rsi),%ymm7,%ymm7

	vpmuludq	%ymm3,%ymm8,%ymm6
	vpmuludq	%ymm4,%ymm8,%ymm2
	vmovdqu	16(%rsi),%xmm8
	vpaddq	%ymm6,%ymm11,%ymm11
	vpaddq	%ymm2,%ymm12,%ymm12
	vmovdqa	16(%rax),%ymm2
	vpmuludq	%ymm1,%ymm9,%ymm6
	vpmuludq	%ymm0,%ymm9,%ymm9
	vpaddq	%ymm6,%ymm14,%ymm14
	vpaddq	%ymm9,%ymm13,%ymm13
	vinserti128	$1,48(%rsi),%ymm8,%ymm8
	leaq	64(%rsi),%rsi

	vpmuludq	%ymm1,%ymm2,%ymm6
	vpmuludq	%ymm0,%ymm2,%ymm2
	vpsrldq	$6,%ymm7,%ymm9
	vpaddq	%ymm6,%ymm15,%ymm15
	vpaddq	%ymm2,%ymm14,%ymm14
	vpmuludq	%ymm3,%ymm10,%ymm6
	vpmuludq	%ymm4,%ymm10,%ymm2
	vpsrldq	$6,%ymm8,%ymm10
	vpaddq	%ymm6,%ymm12,%ymm12
	vpaddq	%ymm2,%ymm13,%ymm13
	vpunpckhqdq	%ymm8,%ymm7,%ymm6

	vpmuludq	%ymm3,%ymm5,%ymm3
	vpmuludq	%ymm4,%ymm5,%ymm4
	vpunpcklqdq	%ymm8,%ymm7,%ymm7
	vpaddq	%ymm3,%ymm13,%ymm2
	vpaddq	%ymm4,%ymm14,%ymm3
	vpunpcklqdq	%ymm10,%ymm9,%ymm10
	vpmuludq	80(%rax),%ymm0,%ymm4
	vpmuludq	%ymm1,%ymm5,%ymm0
	vmovdqa	64(%rcx),%ymm5
	vpaddq	%ymm4,%ymm15,%ymm4
	vpaddq	%ymm0,%ymm11,%ymm0




	vpsrlq	$26,%ymm3,%ymm14
	vpand	%ymm5,%ymm3,%ymm3
	vpaddq	%ymm14,%ymm4,%ymm4

	vpsrlq	$26,%ymm0,%ymm11
	vpand	%ymm5,%ymm0,%ymm0
	vpaddq	%ymm11,%ymm12,%ymm1

	vpsrlq	$26,%ymm4,%ymm15
	vpand	%ymm5,%ymm4,%ymm4

	vpsrlq	$4,%ymm10,%ymm9

	vpsrlq	$26,%ymm1,%ymm12
	vpand	%ymm5,%ymm1,%ymm1
	vpaddq	%ymm12,%ymm2,%ymm2

	vpaddq	%ymm15,%ymm0,%ymm0
	vpsllq	$2,%ymm15,%ymm15
	vpaddq	%ymm15,%ymm0,%ymm0

	vpand	%ymm5,%ymm9,%ymm9
	vpsrlq	$26,%ymm7,%ymm8

	vpsrlq	$26,%ymm2,%ymm13
	vpand	%ymm5,%ymm2,%ymm2
	vpaddq	%ymm13,%ymm3,%ymm3

	vpaddq	%ymm9,%ymm2,%ymm2
	vpsrlq	$30,%ymm10,%ymm10

	vpsrlq	$26,%ymm0,%ymm11
	vpand	%ymm5,%ymm0,%ymm0
	vpaddq	%ymm11,%ymm1,%ymm1

	vpsrlq	$40,%ymm6,%ymm6

	vpsrlq	$26,%ymm3,%ymm14
	vpand	%ymm5,%ymm3,%ymm3
	vpaddq	%ymm14,%ymm4,%ymm4

	vpand	%ymm5,%ymm7,%ymm7
	vpand	%ymm5,%ymm8,%ymm8
	vpand	%ymm5,%ymm10,%ymm10
	vpor	32(%rcx),%ymm6,%ymm6

	subq	$64,%rdx
	jnz	.Loop_avx2

.byte	0x66,0x90
.Ltail_avx2:







	vpaddq	%ymm0,%ymm7,%ymm0
	vmovdqu	4(%rsp),%ymm7
	vpaddq	%ymm1,%ymm8,%ymm1
	vmovdqu	36(%rsp),%ymm8
	vpaddq	%ymm3,%ymm10,%ymm3
	vmovdqu	100(%rsp),%ymm9
	vpaddq	%ymm4,%ymm6,%ymm4
	vmovdqu	52(%rax),%ymm10
	vmovdqu	116(%rax),%ymm5

	vpmuludq	%ymm2,%ymm7,%ymm13
	vpmuludq	%ymm2,%ymm8,%ymm14
	vpmuludq	%ymm2,%ymm9,%ymm15
	vpmuludq	%ymm2,%ymm10,%ymm11
	vpmuludq	%ymm2,%ymm5,%ymm12

	vpmuludq	%ymm0,%ymm8,%ymm6
	vpmuludq	%ymm1,%ymm8,%ymm2
	vpaddq	%ymm6,%ymm12,%ymm12
	vpaddq	%ymm2,%ymm13,%ymm13
	vpmuludq	%ymm3,%ymm8,%ymm6
	vpmuludq	68(%rsp),%ymm4,%ymm2
	vpaddq	%ymm6,%ymm15,%ymm15
	vpaddq	%ymm2,%ymm11,%ymm11

	vpmuludq	%ymm0,%ymm7,%ymm6
	vpmuludq	%ymm1,%ymm7,%ymm2
	vpaddq	%ymm6,%ymm11,%ymm11
	vmovdqu	-12(%rax),%ymm8
	vpaddq	%ymm2,%ymm12,%ymm12
	vpmuludq	%ymm3,%ymm7,%ymm6
	vpmuludq	%ymm4,%ymm7,%ymm2
	vpaddq	%ymm6,%ymm14,%ymm14
	vpaddq	%ymm2,%ymm15,%ymm15

	vpmuludq	%ymm3,%ymm8,%ymm6
	vpmuludq	%ymm4,%ymm8,%ymm2
	vpaddq	%ymm6,%ymm11,%ymm11
	vpaddq	%ymm2,%ymm12,%ymm12
	vmovdqu	20(%rax),%ymm2
	vpmuludq	%ymm1,%ymm9,%ymm6
	vpmuludq	%ymm0,%ymm9,%ymm9
	vpaddq	%ymm6,%ymm14,%ymm14
	vpaddq	%ymm9,%ymm13,%ymm13

	vpmuludq	%ymm1,%ymm2,%ymm6
	vpmuludq	%ymm0,%ymm2,%ymm2
	vpaddq	%ymm6,%ymm15,%ymm15
	vpaddq	%ymm2,%ymm14,%ymm14
	vpmuludq	%ymm3,%ymm10,%ymm6
	vpmuludq	%ymm4,%ymm10,%ymm2
	vpaddq	%ymm6,%ymm12,%ymm12
	vpaddq	%ymm2,%ymm13,%ymm13

	vpmuludq	%ymm3,%ymm5,%ymm3
	vpmuludq	%ymm4,%ymm5,%ymm4
	vpaddq	%ymm3,%ymm13,%ymm2
	vpaddq	%ymm4,%ymm14,%ymm3
	vpmuludq	84(%rax),%ymm0,%ymm4
	vpmuludq	%ymm1,%ymm5,%ymm0
	vmovdqa	64(%rcx),%ymm5
	vpaddq	%ymm4,%ymm15,%ymm4
	vpaddq	%ymm0,%ymm11,%ymm0




	vpsrldq	$8,%ymm12,%ymm8
	vpsrldq	$8,%ymm2,%ymm9
	vpsrldq	$8,%ymm3,%ymm10
	vpsrldq	$8,%ymm4,%ymm6
	vpsrldq	$8,%ymm0,%ymm7
	vpaddq	%ymm8,%ymm12,%ymm12
	vpaddq	%ymm9,%ymm2,%ymm2
	vpaddq	%ymm10,%ymm3,%ymm3
	vpaddq	%ymm6,%ymm4,%ymm4
	vpaddq	%ymm7,%ymm0,%ymm0

	vpermq	$0x2,%ymm3,%ymm10
	vpermq	$0x2,%ymm4,%ymm6
	vpermq	$0x2,%ymm0,%ymm7
	vpermq	$0x2,%ymm12,%ymm8
	vpermq	$0x2,%ymm2,%ymm9
	vpaddq	%ymm10,%ymm3,%ymm3
	vpaddq	%ymm6,%ymm4,%ymm4
	vpaddq	%ymm7,%ymm0,%ymm0
	vpaddq	%ymm8,%ymm12,%ymm12
	vpaddq	%ymm9,%ymm2,%ymm2




	vpsrlq	$26,%ymm3,%ymm14
	vpand	%ymm5,%ymm3,%ymm3
	vpaddq	%ymm14,%ymm4,%ymm4

	vpsrlq	$26,%ymm0,%ymm11
	vpand	%ymm5,%ymm0,%ymm0
	vpaddq	%ymm11,%ymm12,%ymm1

	vpsrlq	$26,%ymm4,%ymm15
	vpand	%ymm5,%ymm4,%ymm4

	vpsrlq	$26,%ymm1,%ymm12
	vpand	%ymm5,%ymm1,%ymm1
	vpaddq	%ymm12,%ymm2,%ymm2

	vpaddq	%ymm15,%ymm0,%ymm0
	vpsllq	$2,%ymm15,%ymm15
	vpaddq	%ymm15,%ymm0,%ymm0

	vpsrlq	$26,%ymm2,%ymm13
	vpand	%ymm5,%ymm2,%ymm2
	vpaddq	%ymm13,%ymm3,%ymm3

	vpsrlq	$26,%ymm0,%ymm11
	vpand	%ymm5,%ymm0,%ymm0
	vpaddq	%ymm11,%ymm1,%ymm1

	vpsrlq	$26,%ymm3,%ymm14
	vpand	%ymm5,%ymm3,%ymm3
	vpaddq	%ymm14,%ymm4,%ymm4

	vmovd	%xmm0,-112(%rdi)
	vmovd	%xmm1,-108(%rdi)
	vmovd	%xmm2,-104(%rdi)
	vmovd	%xmm3,-100(%rdi)
	vmovd	%xmm4,-96(%rdi)
	vmovdqa	80(%r11),%xmm6
	vmovdqa	96(%r11),%xmm7
	vmovdqa	112(%r11),%xmm8
	vmovdqa	128(%r11),%xmm9
	vmovdqa	144(%r11),%xmm10
	vmovdqa	160(%r11),%xmm11
	vmovdqa	176(%r11),%xmm12
	vmovdqa	192(%r11),%xmm13
	vmovdqa	208(%r11),%xmm14
	vmovdqa	224(%r11),%xmm15
	leaq	248(%r11),%rsp
.Ldo_avx2_epilogue:
	vzeroupper
	movq	8(%rsp),%rdi
	movq	16(%rsp),%rsi
	.byte	0xf3,0xc3

.LSEH_end_crypton_poly1305_asm_blocks_avx2:
.p2align	6
.Lconst:
.Lmask24:
.long	0x0ffffff,0,0x0ffffff,0,0x0ffffff,0,0x0ffffff,0
.L129:
.long	16777216,0,16777216,0,16777216,0,16777216,0
.Lmask26:
.long	0x3ffffff,0,0x3ffffff,0,0x3ffffff,0,0x3ffffff,0
.Lpermd_avx2:
.long	2,2,2,3,2,0,2,1
.Lpermd_avx512:
.long	0,0,0,1, 0,2,0,3, 0,4,0,5, 0,6,0,7

.L2_44_inp_permd:
.long	0,1,1,2,2,3,7,7
.L2_44_inp_shift:
.quad	0,12,24,64
.L2_44_mask:
.quad	0xfffffffffff,0xfffffffffff,0x3ffffffffff,0xffffffffffffffff
.L2_44_shift_rgt:
.quad	44,44,42,64
.L2_44_shift_lft:
.quad	8,8,10,64

.p2align	6
.Lx_mask44:
.quad	0xfffffffffff,0xfffffffffff,0xfffffffffff,0xfffffffffff
.quad	0xfffffffffff,0xfffffffffff,0xfffffffffff,0xfffffffffff
.Lx_mask42:
.quad	0x3ffffffffff,0x3ffffffffff,0x3ffffffffff,0x3ffffffffff
.quad	0x3ffffffffff,0x3ffffffffff,0x3ffffffffff,0x3ffffffffff
.byte	80,111,108,121,49,51,48,53,32,102,111,114,32,120,56,54,95,54,52,44,32,67,82,89,80,84,79,71,65,77,83,32,98,121,32,64,100,111,116,45,97,115,109,0
.p2align	4
.globl	crypton_xor128_encrypt_n_pad
.def	crypton_xor128_encrypt_n_pad;	.scl 2;	.type 32;	.endef
.p2align	4
crypton_xor128_encrypt_n_pad:
	.byte	0xf3,0x0f,0x1e,0xfa

	subq	%r8,%rdx
	subq	%r8,%rcx
	movq	%r9,%r10
	shrq	$4,%r9
	jz	.Ltail_enc
	nop
.Loop_enc_xmm:
	movdqu	(%rdx,%r8,1),%xmm0
	pxor	(%r8),%xmm0
	movdqu	%xmm0,(%rcx,%r8,1)
	movdqa	%xmm0,(%r8)
	leaq	16(%r8),%r8
	decq	%r9
	jnz	.Loop_enc_xmm

	andq	$15,%r10
	jz	.Ldone_enc

.Ltail_enc:
	movq	$16,%r9
	subq	%r10,%r9
	xorl	%eax,%eax
.Loop_enc_byte:
	movb	(%rdx,%r8,1),%al
	xorb	(%r8),%al
	movb	%al,(%rcx,%r8,1)
	movb	%al,(%r8)
	leaq	1(%r8),%r8
	decq	%r10
	jnz	.Loop_enc_byte

	xorl	%eax,%eax
.Loop_enc_pad:
	movb	%al,(%r8)
	leaq	1(%r8),%r8
	decq	%r9
	jnz	.Loop_enc_pad

.Ldone_enc:
	movq	%r8,%rax
	.byte	0xf3,0xc3


.globl	crypton_xor128_decrypt_n_pad
.def	crypton_xor128_decrypt_n_pad;	.scl 2;	.type 32;	.endef
.p2align	4
crypton_xor128_decrypt_n_pad:
	.byte	0xf3,0x0f,0x1e,0xfa

	subq	%r8,%rdx
	subq	%r8,%rcx
	movq	%r9,%r10
	shrq	$4,%r9
	jz	.Ltail_dec
	nop
.Loop_dec_xmm:
	movdqu	(%rdx,%r8,1),%xmm0
	movdqa	(%r8),%xmm1
	pxor	%xmm0,%xmm1
	movdqu	%xmm1,(%rcx,%r8,1)
	movdqa	%xmm0,(%r8)
	leaq	16(%r8),%r8
	decq	%r9
	jnz	.Loop_dec_xmm

	pxor	%xmm1,%xmm1
	andq	$15,%r10
	jz	.Ldone_dec

.Ltail_dec:
	movq	$16,%r9
	subq	%r10,%r9
	xorl	%eax,%eax
	xorq	%r11,%r11
.Loop_dec_byte:
	movb	(%rdx,%r8,1),%r11b
	movb	(%r8),%al
	xorb	%r11b,%al
	movb	%al,(%rcx,%r8,1)
	movb	%r11b,(%r8)
	leaq	1(%r8),%r8
	decq	%r10
	jnz	.Loop_dec_byte

	xorl	%eax,%eax
.Loop_dec_pad:
	movb	%al,(%r8)
	leaq	1(%r8),%r8
	decq	%r9
	jnz	.Loop_dec_pad

.Ldone_dec:
	movq	%r8,%rax
	.byte	0xf3,0xc3


.def	se_handler;	.scl 3;	.type 32;	.endef
.p2align	4
se_handler:
	.byte	0xf3,0x0f,0x1e,0xfa

	pushq	%rsi
	pushq	%rdi
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	pushfq
	subq	$64,%rsp

	movq	120(%r8),%rax
	movq	248(%r8),%rbx

	movq	8(%r9),%rsi
	movq	56(%r9),%r11

	movl	0(%r11),%r10d
	leaq	(%rsi,%r10,1),%r10
	cmpq	%r10,%rbx
	jb	.Lcommon_seh_tail

	movq	152(%r8),%rax

	movl	4(%r11),%r10d
	leaq	(%rsi,%r10,1),%r10
	cmpq	%r10,%rbx
	jae	.Lcommon_seh_tail

	leaq	56(%rax),%rax

	movq	-8(%rax),%rbx
	movq	-16(%rax),%rbp
	movq	-24(%rax),%r12
	movq	-32(%rax),%r13
	movq	-40(%rax),%r14
	movq	-48(%rax),%r15
	movq	%rbx,144(%r8)
	movq	%rbp,160(%r8)
	movq	%r12,216(%r8)
	movq	%r13,224(%r8)
	movq	%r14,232(%r8)
	movq	%r15,240(%r8)

	jmp	.Lcommon_seh_tail


.def	avx_handler;	.scl 3;	.type 32;	.endef
.p2align	4
avx_handler:
	.byte	0xf3,0x0f,0x1e,0xfa

	pushq	%rsi
	pushq	%rdi
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	pushfq
	subq	$64,%rsp

	movq	120(%r8),%rax
	movq	248(%r8),%rbx

	movq	8(%r9),%rsi
	movq	56(%r9),%r11

	movl	0(%r11),%r10d
	leaq	(%rsi,%r10,1),%r10
	cmpq	%r10,%rbx
	jb	.Lcommon_seh_tail

	movq	152(%r8),%rax

	movl	4(%r11),%r10d
	leaq	(%rsi,%r10,1),%r10
	cmpq	%r10,%rbx
	jae	.Lcommon_seh_tail

	movq	208(%r8),%rax

	leaq	80(%rax),%rsi
	leaq	248(%rax),%rax
	leaq	512(%r8),%rdi
	movl	$20,%ecx
.long	0xa548f3fc

.Lcommon_seh_tail:
	movq	8(%rax),%rdi
	movq	16(%rax),%rsi
	movq	%rax,152(%r8)
	movq	%rsi,168(%r8)
	movq	%rdi,176(%r8)

	movq	40(%r9),%rdi
	movq	%r8,%rsi
	movl	$154,%ecx
.long	0xa548f3fc

	movq	%r9,%rsi
	xorq	%rcx,%rcx
	movq	8(%rsi),%rdx
	movq	0(%rsi),%r8
	movq	16(%rsi),%r9
	movq	40(%rsi),%r10
	leaq	56(%rsi),%r11
	leaq	24(%rsi),%r12
	movq	%r10,32(%rsp)
	movq	%r11,40(%rsp)
	movq	%r12,48(%rsp)
	movq	%rcx,56(%rsp)
	call	*__imp_RtlVirtualUnwind(%rip)

	movl	$1,%eax
	addq	$64,%rsp
	popfq
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	popq	%rdi
	popq	%rsi
	.byte	0xf3,0xc3


.section	.pdata
.p2align	2
.rva	.LSEH_begin_crypton_poly1305_asm_init
.rva	.LSEH_end_crypton_poly1305_asm_init
.rva	.LSEH_info_crypton_poly1305_asm_init

.rva	.LSEH_begin_crypton_poly1305_asm_blocks
.rva	.LSEH_end_crypton_poly1305_asm_blocks
.rva	.LSEH_info_crypton_poly1305_asm_blocks

.rva	.LSEH_begin_crypton_poly1305_asm_emit
.rva	.LSEH_end_crypton_poly1305_asm_emit
.rva	.LSEH_info_crypton_poly1305_asm_emit
.rva	.LSEH_begin_crypton_poly1305_asm_blocks_avx
.rva	.Lbase2_64_avx
.rva	.LSEH_info_crypton_poly1305_asm_blocks_avx_1

.rva	.Lbase2_64_avx
.rva	.Leven_avx
.rva	.LSEH_info_crypton_poly1305_asm_blocks_avx_2

.rva	.Leven_avx
.rva	.LSEH_end_crypton_poly1305_asm_blocks_avx
.rva	.LSEH_info_crypton_poly1305_asm_blocks_avx_3
.rva	.LSEH_begin_crypton_poly1305_asm_blocks_avx2
.rva	.Lbase2_64_avx2
.rva	.LSEH_info_crypton_poly1305_asm_blocks_avx2_1

.rva	.Lbase2_64_avx2
.rva	.Leven_avx2
.rva	.LSEH_info_crypton_poly1305_asm_blocks_avx2_2

.rva	.Leven_avx2
.rva	.LSEH_end_crypton_poly1305_asm_blocks_avx2
.rva	.LSEH_info_crypton_poly1305_asm_blocks_avx2_3
.section	.xdata
.p2align	3
.LSEH_info_crypton_poly1305_asm_init:
.byte	9,0,0,0
.rva	se_handler
.long	0,0

.LSEH_info_crypton_poly1305_asm_blocks:
.byte	9,0,0,0
.rva	se_handler
.rva	.Lblocks_body,.Lblocks_epilogue

.LSEH_info_crypton_poly1305_asm_emit:
.byte	9,0,0,0
.rva	se_handler
.long	0,0
.LSEH_info_crypton_poly1305_asm_blocks_avx_1:
.byte	9,0,0,0
.rva	se_handler
.rva	.Lblocks_avx_body,.Lblocks_avx_epilogue

.LSEH_info_crypton_poly1305_asm_blocks_avx_2:
.byte	9,0,0,0
.rva	se_handler
.rva	.Lbase2_64_avx_body,.Lbase2_64_avx_epilogue

.LSEH_info_crypton_poly1305_asm_blocks_avx_3:
.byte	9,0,0,0
.rva	avx_handler
.rva	.Ldo_avx_body,.Ldo_avx_epilogue
.LSEH_info_crypton_poly1305_asm_blocks_avx2_1:
.byte	9,0,0,0
.rva	se_handler
.rva	.Lblocks_avx2_body,.Lblocks_avx2_epilogue

.LSEH_info_crypton_poly1305_asm_blocks_avx2_2:
.byte	9,0,0,0
.rva	se_handler
.rva	.Lbase2_64_avx2_body,.Lbase2_64_avx2_epilogue

.LSEH_info_crypton_poly1305_asm_blocks_avx2_3:
.byte	9,0,0,0
.rva	avx_handler
.rva	.Ldo_avx2_body,.Ldo_avx2_epilogue
