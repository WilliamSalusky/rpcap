#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <event.h>
#include <pcap.h>

#include <stdint.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>


int main(int argc, char **argv)
{
    int sock;
    struct sockaddr_in inaddr;
    uint32_t addr;
    struct iovec vec[6];

    addr = inet_addr("127.0.0.1");
    inaddr.sin_family = AF_INET;
    inaddr.sin_addr.s_addr = addr;
    inaddr.sin_port = htons(1025);

    sock = socket(PF_INET, SOCK_STREAM, 0);
    connect(sock, (struct sockaddr *)&inaddr, sizeof(inaddr));

    char *dev = "eth0";
    char *bpf = "port not 22";
    uint8_t dev_sz = strlen(dev);
    uint32_t bpf_sz = strlen(bpf);
    uint16_t snaplen = 1024;
    uint8_t opts = 0;

    vec[0].iov_base = &dev_sz;
    vec[0].iov_len  = sizeof(dev_sz);
    vec[1].iov_base = &bpf_sz;
    vec[1].iov_len  = sizeof(bpf_sz);
    vec[2].iov_base = &snaplen;
    vec[2].iov_len  = sizeof(snaplen);
    vec[3].iov_base = &opts;
    vec[3].iov_len  = sizeof(opts);
    vec[4].iov_base = dev;
    vec[4].iov_len  = dev_sz;
    vec[5].iov_base = bpf;
    vec[5].iov_len  = bpf_sz;


    writev(sock, vec, 6);

    while(1)
    {
	char data[5000];
	if(recv(sock, data, 5000, 0) <= 0)
	    break;
    }
    return 0;
}


