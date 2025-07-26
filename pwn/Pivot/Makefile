CC = gcc
CFLAGS+= -g -fno-stack-protector -m64 -Wall -no-pie

BINARY=pivot

all: $(BINARY)

$(BINARY): pivot.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -rf pivot

