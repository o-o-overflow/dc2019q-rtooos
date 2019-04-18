; Define kernel_main as an external function

global _main
global _halt
global _syscall_entry
global _register_syscall

MSR_STAR equ 0xc0000081
MSR_LSTAR equ 0xc0000082
MSR_CSTAR equ 0xc0000083
MSR_SYSCALL_MASK equ 0xc0000084
FMASK equ 0x3f7fd5
KERNEL_BASE_OFFSET equ 0x8000000000

extern _kernel_main

section .text

_main:
	mov rdx, [rsp] ; argc
	lea rcx, [rsp + 8] ; argv
	;call _register_syscall
	call _kernel_main
	nop
	jmp _halt
_halt:
mov edx, 12
int 0x80
	hlt
	jmp _halt

_register_syscall:
	xor rax, rax
	mov rdx, 0x00200008
	mov edx, MSR_STAR
	wrmsr

	mov eax, FMASK
	xor rdx, rdx
	mov ecx, MSR_SYSCALL_MASK
	wrmsr

	lea rax, [rel _syscall_entry]
	mov rdx, KERNEL_BASE_OFFSET
	mov ecx, MSR_LSTAR
	wrmsr
	ret
	ret

_syscall_entry:
	jmp _syscall_entry


section .data

msg:    db      "oooverflow", 10
.len:   equ     $ - msg
