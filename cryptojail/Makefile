
.PHONY: all clean
all: server.zip

clean:
	rm -f server.zip requires-server

server.zip:
	echo 'python3 jail.py' > requires-server
	zip server.zip jail.py requires-server flag.txt
