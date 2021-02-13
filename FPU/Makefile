C=gcc
CFLAGS=-m64 -g -fno-stack-protector -no-pie -z norelro

all: challenge.zip server.zip

binary:
	$(CC) $(CFLAGS) -o floating_point_dungeon floating_point_dungeon.c


challenge.zip: binary
    zip challenge.zip floating_point_dungeon &&\

server.zip: binary
    zip server.zip floating_point_dungeon flag.txt &&\
    echo floating_point_dungeon > requires-server

clean:
	rm -rf floating_point_dungeon challenge.zip server.zip requires-server

