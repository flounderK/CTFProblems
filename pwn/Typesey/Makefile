CC=gcc
CFLAGS+=-m64 -g -no-pie -z norelro

.PHONY: all binary clean

all: typesey

typesey: typesey.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f typesey

