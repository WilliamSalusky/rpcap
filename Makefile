CFLAGS   = -DDEBUG -Wall -ggdb 

all: rpcap-server rpcap-client

rpcap-server: rpcap-server.c iov.o
	gcc $(CFLAGS) rpcap-server.c -o rpcap-server iov.o -levent -lpcap  

rpcap-client: rpcap-client.c config.o iov.o
	gcc $(CFLAGS) rpcap-client.c -o rpcap-client config.o iov.o -levent -lconfuse

clean:
	rm -rf rpcap-server rpcap-client *.o 
	
