CC = gcc
CFLAGS= -g -fno-stack-protector -m64 -Wall -no-pie

all: binary challenge.zip server.zip

binary:
	$(CC) $(CFLAGS) -o easy_rop easy_rop.c

challenge.zip: binary
	zip challenge.zip easy_rop libc*.so

server.zip: binary
	echo easy_rop > requires-server &&\
    zip server.zip easy_rop flag.txt requires-server

clean:
	rm -rf challenge.zip server.zip requires-server easy_rop

