global _putchar
global _putqword
global _readstr
global _puts
global _getdirents
global _catfile

section .text

_putchar:
	mov rax, rdi ; value in rax
	mov rdi, 0x61 ; hypercall_putchar
	out dx, al
	ret

_putqword:
	mov rax, rdi ; value in rax
	mov rdi, 0x62 ; hypercall_putqword
	out dx, al
	ret

_readstr:
	mov rax, rdi ; ptr goes into rax
	mov rdi, 0x63 ; hypercall number
	mov rsi, rsi ; length of string to read
	out dx, al ; boomo
	; here rax will have the value of the length
	ret

_puts:
	mov rax, rdi ; value in rax
	mov rdi, 0x64 ; hypercall_putstr
	out dx, al
	ret

_getdirents:
	mov rdi, 0x65
	out dx, al
	ret

_catfile:
	mov rax, rdi
	mov rdi, 0x66
	out dx, al
	ret
