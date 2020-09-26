all: challenge.zip server.zip

challenge.zip:
	zip challenge.zip jail.js

server.zip:
	echo jail.js > requires-server &&\
    zip server.zip jail.js flag.txt requires-server

clean:
	rm challenge.zip server.zip requires-server

