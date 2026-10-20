# What crt1.o's start does on i386: argc, argv and envp from the stack to main, then exit.
	.text
	.globl start
start:
	pushl	$0
	movl	%esp, %ebp
	andl	$-16, %esp
	subl	$16, %esp
	movl	4(%ebp), %ebx
	movl	%ebx, 0(%esp)
	leal	8(%ebp), %ecx
	movl	%ecx, 4(%esp)
	leal	12(%ebp,%ebx,4), %edx
	movl	%edx, 8(%esp)
	call	_main
	movl	%eax, 0(%esp)
	call	_exit
	hlt
