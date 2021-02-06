
CC=gcc
CFLAGS=-m64 -g -Wall -no-pie

export BINARYNAME=mythicalclassregistration

.PHONY: all clean build

all: clean build challenge.zip server.zip

build: binary

binary:
	$(CC) $(CFLAGS) mythicalclassregistration.c -o $(BINARYNAME)

clean:
	rm -f $(BINARYNAME) *.o requires-server challenge.zip server.zip 2>/dev/null

server.zip: binary
	echo $(BINARYNAME) > requires-server &&\
	zip server.zip $(BINARYNAME) flag.txt requires-server

challenge.zip: binary
	zip challenge.zip $(BINARYNAME) *.so



