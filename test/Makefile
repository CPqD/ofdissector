all: server client12 client13

server: server.c net.h
	gcc server.c -o server

client12: client12.c net.h
	gcc client12.c -o client12 -I../src/openflow

client13: client13.c net.h
	gcc client13.c -o client13 -I../src/openflow

clean:
	rm -rf server client
