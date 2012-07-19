all: server client

server: server.c net.h
	gcc server.c -o server

client: client.c net.h
	gcc client.c -o client -I../src/openflow

clean:
	rm -rf server client
