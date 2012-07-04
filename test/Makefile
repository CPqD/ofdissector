all: server client

server: server.c
	gcc server.c -o server

client: client.c
	gcc client.c -o client -I../src/openflow

clean:
	rm -rf server client
