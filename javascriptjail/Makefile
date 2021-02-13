all: challenge.zip server.zip

challenge.zip:
	zip challenge.zip jail.js

server.zip:
	echo 'node jail.js' > requires-server &&\
    zip server.zip jail.js flag.txt requires-server

clean:
	rm -f challenge.zip server.zip requires-server

