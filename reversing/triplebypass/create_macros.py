#!/usr/bin/python3
import argparse
import math
import re
import functools


def main(args):
    with open(args.filepath, "r") as f:
        lyrics = f.read().splitlines()

    if args.flag is None:
        line_list = ', '.join(f'"{i}"' for i in lyrics)
        output = f"{{ {line_list} }}"
        output = output.replace('"', '\\"')
        output = f"\"{output}\""
        print(output)
    else:
        pseudo_key = sum([getencodedline(s, i) for i, s in enumerate(lyrics)])
        print(pseudo_key)
        hidden_flag_bytes = safe_xor(args.flag.encode(), pseudo_key)
        print(hidden_flag_bytes)
        # print(hidden_flag_bytes)
        hidden_flag = int.from_bytes(hidden_flag_bytes, byteorder='big')
        print(hex(hidden_flag))


def safe_xor(a, b):
    if isinstance(a, int) and isinstance(b, int):
        return a ^ b

    if isinstance(a, int):
        a = a.to_bytes(math.ceil(a.bit_length() / 8), 'big')
    if isinstance(b, int):
        b = b.to_bytes(math.ceil(b.bit_length() / 8), 'big')

    longer, shorter = (a, b) if len(a) > len(b) else (b, a)
    if a == b'\x00' or b == b'\x00':
        return b'\x00'*len(longer)
    mult, pad = divmod(len(longer), len(shorter))
    second_field = (shorter*mult) + shorter[:pad + 1]
    res_intlist = [c ^ d for c, d in zip(longer, second_field)]
    result = bytes(res_intlist)
    return result


def getencodedline(line, line_no):
    vowel_rexp = re.compile(r'^[aeiouy]$', re.IGNORECASE)
    consonants = [i for i in line if re.match(vowel_rexp, i) is None]
    vowel_count = len(line) - len(consonants)
    consonant_values = [ord(a) for a in consonants]
    values = [((x ^ vowel_count) ^ (line_no + 1)) for x in consonant_values]
    result = functools.reduce((lambda x, y: (x*10)+y), values, 0)
    print(f"{line_no}: {result}")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("filepath",
                        help="Path of the file you need info about")
    parser.add_argument("-f", "--flag",
                        help="The flag you want in this binary")
    args = parser.parse_args()
    main(args)

