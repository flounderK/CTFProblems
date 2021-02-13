
.PHONY: all clean
all: server.zip

clean:
	rm -f server.zip requires-server

server.zip:
	zip server.zip jail.py flag.txt
	echo 'python3 jail.py' > requires-server
