

.PHONY: all clean

all: chal.s challenge.zip

challenge.zip: chal.s
	zip challenge.zip chal.s

chal.s:
	python3 genchal.py `cat flag.txt` > chal.s

clean:
	rm -f chal chal.o chal.s challenge.zip
