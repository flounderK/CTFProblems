C=gcc
CFLAGS=-m64 -g -fno-stack-protector -no-pie -z norelro

all: challenge.zip server.zip

challenge.zip:
	$(CC) $(CFLAGS) -o calling_convention calling_convention.c &&\
    zip challenge.zip calling_convention &&\
    rm calling_convention

server.zip:
	$(CC) $(CFLAGS) -o calling_convention calling_convention.c &&\
    zip server.zip calling_convention flag.txt &&\
    rm calling_convention &&\
    echo calling_convention > requires-server

clean:
	rm challenge.zip server.zip requires-server

