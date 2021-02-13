C=gcc
CFLAGS=-m64 -g -no-pie -z norelro

.PHONY: all binary clean

all: binary challenge.zip server.zip

binary:
	$(CC) $(CFLAGS) -o prints prints.c

challenge.zip: binary
	zip challenge.zip prints

server.zip: binary
	zip server.zip prints flag.txt &&\
    echo prints > requires-server

clean:
	rm -f prints challenge.zip server.zip requires-server

