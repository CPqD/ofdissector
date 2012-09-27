all: server client

server: server.c net.h
	gcc server.c -o server

client: client13.c net.h
	gcc client13.c -o client -I../src/openflow

clean:
	rm -rf server client
