#!/usr/bin/python3
from pwn import *

context.terminal = ['termite', '-e']
context.binary = binary = ELF('mythicalclassregistration')

p = process(binary.path)

gdb.attach(p)
