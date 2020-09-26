C=gcc
CFLAGS=-m64 -g -fno-stack-protector -no-pie -z norelro

all: challenge.zip server.zip

challenge.zip:
	$(CC) $(CFLAGS) -o floating_point_dungeon floating_point_dungeon.c &&\
    zip challenge.zip floating_point_dungeon &&\
    rm floating_point_dungeon

server.zip:
	$(CC) $(CFLAGS) -o floating_point_dungeon floating_point_dungeon.c &&\
    zip server.zip floating_point_dungeon flag.txt &&\
    rm floating_point_dungeon &&\
    echo floating_point_dungeon > requires-server

clean:
	rm challenge.zip server.zip requires-server

