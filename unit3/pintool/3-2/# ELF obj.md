# ELF obj. file format
## code + data
* ELF is architecture independent (32 and 64 bit bins both use ELF)
* .text of each program looks different (.text = code)

### loading executable obj files:

    visualize it as a tree*
    
    64 and 32bit have different loaders (the loader is a counter part i.e. in userspace for fork() and clone() in kernel-land)

    `_start` elf's program start
    which goes to the systems libc (__libc_start_main)


    so who makes the decision to place got and plt and if got is writeable?
    the loader is responsible for that!!!


    so the order goes:
    kernal, loader, libc, main


    basic block ===  block of inst with a jmp (control flow)



# Pintool 10/22/24
    dynamic binary instrumentation
    