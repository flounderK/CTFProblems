
.PHONY: all clean

all: server.zip

server.zip:
	echo 'python3 CommunicationSkills.py' > requires-server
	zip server.zip CommunicationSkills.py requires-server flag.txt

clean:
	rm -f requires-server server.zip
