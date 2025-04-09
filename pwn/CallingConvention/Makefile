C=gcc
CFLAGS+=-m64 -g -fno-stack-protector -no-pie -z norelro

.PHONY: all binary clean

all: binary challenge.zip server.zip

binary:
	$(CC) $(CFLAGS) -o calling_convention calling_convention.c

challenge.zip: binary
	zip challenge.zip calling_convention

server.zip: binary
	echo './calling_convention' > requires-server
	zip server.zip calling_convention flag.txt requires-server

clean:
	rm -rf calling_convention challenge.zip server.zip requires-server

