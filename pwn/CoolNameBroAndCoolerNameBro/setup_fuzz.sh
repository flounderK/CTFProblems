#!/bin/bash

rm -rf cool_name_bro.{bb,asan,ubsan,cmplog,gcov}
rm -rf inputs outputs
make clean

make CC=afl-clang-lto
cp build/debug/cool_name_bro cool_name_bro.bb
make clean

AFL_USE_ASAN=1 make CC=afl-clang-fast
cp build/debug/cool_name_bro cool_name_bro.asan
make clean

AFL_USE_UBSAN=1 make CC=afl-clang-lto
cp build/debug/cool_name_bro cool_name_bro.ubsan
make clean

AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto
cp build/debug/cool_name_bro cool_name_bro.cmplog
make clean


CFLAGS="-fprofile-arcs -ftest-coverage" make
cp build/debug/cool_name_bro cool_name_bro.gcov

mkdir -p inputs

printf "16\nAAAAAAAAAAAAAAAA\n8\n" > inputs/a

# early crashes from asan
# afl-fuzz -i ./inputs -o ./outputs -c ./cool_name_bro.cmplog -w ./cool_name_bro.asan -w ./cool_name_bro.ubsan -- ./cool_name_bro.bb

# crashes from memory corruption
# afl-fuzz -i ./inputs -o ./outputs -c ./cool_name_bro.cmplog -- ./cool_name_bro.bb

# analyze with cmplog to identify critical paths for triggering crash
# afl-analyze -i san_outputs/default/crashes/id:000022,sig:06,src:000043,time:246727,execs:29630,op:havoc,rep:12 -- ./cool_name_bro.cmplog

# generate lcov web report showing code coverage of source code
# afl-cov -d outputs --coverage-cmd "./cool_name_bro.gcov" --overwrite --code-dir .

# show all of the different crash locations and detected crash types that asan finds
# for i in $(find outputs/default/crashes -type f ); do ./cool_name_bro.asan < $i 2>&1; done | grep 'at pc'
