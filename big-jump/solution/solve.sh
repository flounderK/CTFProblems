#!/bin/sh

nasm -f elf64 $1 -o chal.o
ld chal.o -o chal
./chal
