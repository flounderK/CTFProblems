

export BINARYNAME=magicalbillygoat
.PHONY: all clean build

all: clean build

challenge.zip: binary
	zip challenge.zip $(BINARYNAME)

build:
	go tool compile -E -v magicalbillygoat.go
	go tool link -o $(BINARYNAME) magicalbillygoat.o
	# works, but provides no debug output
	# go build magicalbillygoat.go

clean:
	rm -f *.o $(BINARYNAME) chow.down challenge.zip 2>/dev/null


