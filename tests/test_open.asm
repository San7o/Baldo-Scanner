SECTION .data
filename   db   "shell.nix", 0x0

SECTION .bss
file_data:    RESB    255


SECTION .text
global _start         ; subroutine, must be declared for linker (ld)
_start:
    ; open
    mov   rdi, filename
    mov   rsi, 0
    mov   rdx, 0666
    mov   rax, 2
    syscall
    ; read
    mov   rdi, rax
    mov   rax, 0
    mov   rsi, file_data
    mov   rdx, 10
    syscall
    ; print
    mov   rdi, 1    
    mov   rax, 1         ; system call for sys_write
    mov   rsi, file_data
    mov   rdx, 10     
    syscall

    mov   rax, 0x3c      ; system call for sys_exit
    mov   rdi, 0         ; exit code 0
    syscall
    ret
