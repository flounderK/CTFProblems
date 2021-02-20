C=gcc
CFLAGS=-m64 -g -no-pie -z norelro

.PHONY: all binary clean

all: binary challenge.zip server.zip

binary:
	$(CC) $(CFLAGS) -o prints prints.c

challenge.zip: binary
	zip challenge.zip prints

server.zip: binary
	echo prints > requires-server
	zip server.zip prints requires-server flag.txt

clean:
	rm -f prints challenge.zip server.zip requires-server

