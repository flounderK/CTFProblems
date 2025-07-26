CC=gcc
CFLAGS+=-m64 -g -no-pie -z norelro

.PHONY: all binary clean

all: prints prints_easy

prints: prints.c
	$(CC) $(CFLAGS) -o $@ $^


prints_easy: CFLAGS+=-DFLAG_LEAK
prints_easy: prints.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f prints prints_easy

