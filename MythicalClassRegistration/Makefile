
CC=gcc
CFLAGS=-m64 -g -Wall

export BINARYNAME=mythicalclassregistration

.PHONY: all clean build

all: build

build: binary

binary:
	$(CC) $(CFLAGS) mythicalclassregistration.c -o $(BINARYNAME)

clean:
	rm -f $(BINARYNAME) *.o *.so 2>/dev/null
