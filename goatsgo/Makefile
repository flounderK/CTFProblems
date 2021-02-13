

export BINARYNAME=magicalbillygoat
.PHONY: all clean build

all: clean build


build:
	go tool compile -E -v magicalbillygoat.go
	go tool link -o $(BINARYNAME) magicalbillygoat.o
	# works, but provides no debug output
	# go build magicalbillygoat.go

clean:
	rm -f *.o $(BINARYNAME) chow.down 2>/dev/null


