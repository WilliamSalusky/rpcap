CFLAGS   = -DDEBUG -Wall -ggdb 

all: rpcap-server rpcap-client

rpcap-server: rpcap-server.c iov.o
	gcc $(CFLAGS) rpcap-server.c -o rpcap-server iov.o -levent -lpcap  

rpcap-client: rpcap-client.c iov.o
	gcc $(CFLAGS) rpcap-client.c -o rpcap-client iov.o -levent

clean:
	rm -rf rpcap-server rpcap-client *.o 
	
