#!/usr/bin/python3

from pwn import *
import re
import argparse
import random
import hashlib

context.arch = 'amd64'

parser = argparse.ArgumentParser(description="""Dumps a quick assembly program that
                                 prints out the flag""")
parser.add_argument('flag', help='flag')
parser.add_argument('-s', '--size', help="Bytes per echo",
                    type=int, default=3)
args = parser.parse_args()


def batch(it, s):
    length = len(it)
    for i in range(0, length, s):
        yield it[i:i+s]


comment_rexp = re.compile(r'/\*.*\*/')

final_chunks = []

code_chunks = [(i, re.sub(comment_rexp, '', shellcraft.echo(chunk)))
               for i, chunk in enumerate(batch(args.flag, args.size))]

for i, c in code_chunks:
    # labels have to start with a letter
    label = 'F' + hashlib.md5(str(i).encode()).hexdigest()[:7]
    prev_suffix = ' '*4 + 'jmp %s\n' % label
    cleaned_chunk = re.sub('SYS_write', str(constants.SYS_write.real), c)
    cleaned_chunk = re.sub('ptr', '', cleaned_chunk)
    xor_match = re.search(r'(0x[a-fA-F0-9]+) \^ (0x[a-fA-F0-9]+)', cleaned_chunk)
    if xor_match is not None:
        a, b = xor_match.groups()
        c = int(a, 16) ^ int(b, 16)
        cleaned_chunk = re.sub(re.escape(xor_match[0]), hex(c), cleaned_chunk)
    if i == len(code_chunks) - 1:
        cleaned_chunk += 'jmp end'
    final_chunks.append(label + ':\n' + cleaned_chunk)

    if i != 0:
        final_chunks[i-1] += prev_suffix



random.shuffle(final_chunks)


program = '\n'.join(['jmp ' + 'F' + hashlib.md5(str(0).encode()).hexdigest()[:7]] + final_chunks)

program += 'end:'
print(program)
