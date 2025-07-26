CC=gcc
CFLAGS+=-m64 -g -no-pie -z norelro

.PHONY: all binary clean

all: aslr_bypass

aslr_bypass: aslr_bypass.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f aslr_bypass

