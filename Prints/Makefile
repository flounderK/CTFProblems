C=gcc
CFLAGS=-m64 -g -no-pie -z norelro

all: challenge.zip server.zip

challenge.zip:
	$(CC) $(CFLAGS) -o prints prints.c &&\
    zip challenge.zip prints &&\
    rm prints

server.zip:
	$(CC) $(CFLAGS) -o prints prints.c &&\
    zip server.zip prints flag.txt &&\
    rm prints &&\
    echo prints > requires-server

clean:
	rm challenge.zip server.zip requires-server

