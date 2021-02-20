#!/usr/bin/python3

import sys
import string
import traceback

alph = string.printable[:-4]
real_stdout_write = sys.stdout.write
real_stderr_write = sys.stderr.write


def rotenc(text):
    return ''.join(i if i not in alph else alph[(alph.index(i) + 13) % len(alph)] for i in text)


def stdout_write(text, *args, **kwargs):
    return real_stdout_write(''.join(rotenc(i) for i in text))


def stderr_write(text, *args, **kwargs):
    return real_stderr_write(''.join(rotenc(i) for i in text))

print("Welcome to cryptojail")
print('For your convenience, \\n has been left intact')

sys.stdout.write = stdout_write
sys.stderr.write = stderr_write
print(open(__file__).read())

while True:
    try:
        print(eval(input(">>> ")))
    except Exception:
        traceback.print_exc()


