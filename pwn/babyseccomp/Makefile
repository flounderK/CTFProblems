CC = gcc
CFLAGS+= -g -fno-stack-protector -m64 -Wall -no-pie
BINARY=baby_seccomp

all: $(BINARY)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

$(BINARY): baby_seccomp.o
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -rf $(BINARY) *.o

