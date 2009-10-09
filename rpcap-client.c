#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <event.h>
#include <pcap.h>
#include <stdint.h>
#include <errno.h>
#include <sys/ioctl.h>
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
#include <linux/if.h>
#include <linux/if_tun.h>
#include <time.h>
#include "iov.h"
#include "rpcap.h"

typedef struct r_dev {
    int sock;
    char *serv;
    char *iface;
    uint16_t port;
    iov_t data;
    struct event event;
} r_dev_t;

void rpcap_read_len(int sock, short which, r_dev_t *dev);

int snaplen;
int flags;
char *bpfstr;
int tunfd;
int persist;

void globals_init(void)
{
    snaplen = 1024;
    flags   = 0;
    bpfstr  = NULL;
    tunfd   = 0;
    persist = 1;
}

void free_rdev(r_dev_t *dev)
{
    reset_iov(&dev->data);
    close(dev->sock);
    free(dev->serv);
    free(dev->iface);
    free(dev);
}

int parse_args(int argc, char **argv)
{
    int c;
    int argcret = 0;

    char help[] = 
	"-b <bpf>:          Global BPF Filter\n"
	"-s <snaplen>       Global Snaplen\n";

    while((c=getopt(argc, argv, "hf:s:")) != -1)
    {
	switch(c)
	{
	    case 'h':
		printf("Usage: %s [opts]\n%s\n", 
			argv[0], help);
		exit(1);
	    case 'f':
		bpfstr = strdup(optarg);
		argcret += 2;
		break;
	    case 's':
		snaplen = atoi(optarg);
		argcret += 2;
		break;
	}
    }
    return argcret;
}

int
tuntap_init(void)
{

    struct ifreq    ifr;
    int             fd,
                    err;
    int sock;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
	return fd;

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TAP|IFF_NO_PI;

    strncpy(ifr.ifr_name, "rpcap0", IFNAMSIZ);

    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
	close(fd);
	return err;
    }


    sock = socket(PF_UNIX, SOCK_STREAM, 0);
    ioctl(sock, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_UP;
    ioctl(sock, SIOCSIFFLAGS, &ifr);
    close(sock);

    return fd;
}

void
rpcap_read_payload(int sock, short which, r_dev_t *dev)
{
    int ioret;

    ioret = read_iov(&dev->data, sock);

    if (ioret < 0)
    {
	free_rdev(dev);
	return;
    }

    if (ioret > 0)
    {
	event_set(&dev->event, sock, EV_READ,
		(void *)rpcap_read_payload, dev);
	event_add(&dev->event, 0);
    }

    if(write(tunfd, dev->data.buf, dev->data.offset) <= 0)
    {
	LOG("Error in tuntap write: %s\n", 
		strerror(errno));
	exit(1);
    }

    reset_iov(&dev->data);

    event_set(&dev->event, sock, EV_READ,
	    (void *)rpcap_read_len, dev);
    event_add(&dev->event, 0);
}

void 
rpcap_read_len(int sock, short which, r_dev_t *dev)
{
    int ioret;
    int toread;

    if (!dev->data.buf)
	initialize_iov(&dev->data, sizeof(uint32_t));

    ioret = read_iov(&dev->data, sock);

    if (ioret < 0)
    {
	LOG("Lost connection to %s (%s)\n",
		dev->serv, strerror(errno));
	free_rdev(dev);
	return;
    }

    if (ioret > 0)
    {
	event_set(&dev->event, sock, EV_READ,
		(void *)rpcap_read_len, dev);
	event_add(&dev->event, 0);
    }

    memcpy(&toread, dev->data.buf, sizeof(uint32_t));
    
    reset_iov(&dev->data);

    initialize_iov(&dev->data, toread);

    event_set(&dev->event, sock, EV_READ,
	    (void *)rpcap_read_payload, dev);
    event_add(&dev->event, 0);
}


void
rpcap_handshake(int sock, short which, r_dev_t *dev)
{
    int ioret;

    if (!dev->data.buf)
    {
	int iface_len;
	int bpfstr_len;

	bpfstr_len = bpfstr?strlen(bpfstr):0;
	iface_len  = strlen(dev->iface);

	initialize_iov(&dev->data,
		sizeof(uint8_t) +
		sizeof(uint32_t) +
		sizeof(uint16_t) +
		sizeof(uint8_t) +
		iface_len + 
		bpfstr_len);

	memcpy(&dev->data.buf[0], &iface_len, sizeof(uint8_t));
	memcpy(&dev->data.buf[1], &bpfstr_len, sizeof(uint32_t));
	memcpy(&dev->data.buf[5], &snaplen, sizeof(uint16_t));
	memcpy(&dev->data.buf[7], &flags, sizeof(uint8_t)); 
	memcpy(&dev->data.buf[8], dev->iface, iface_len);

	if (bpfstr)
	    memcpy(&dev->data.buf[8+iface_len], bpfstr, bpfstr_len);
	
	/*
	if(bpfstr)
	    memcpy(&dev->data.buf[8+iface_len], bpfstr, bpfstr_len);
	    */
    }

    ioret = write_iov(&dev->data, dev->sock);

    if (ioret < 0)
    {
	LOG("Lost connection to %s (%s)\n",
	       dev->serv, strerror(errno));	
	free_rdev(dev);
	return;
    }

    if (ioret > 0)
    {
	event_set(&dev->event, dev->sock, EV_WRITE,
		(void *)rpcap_handshake, (void *)dev);
	event_add(&dev->event, 0);
	return;
    }
    
    reset_iov(&dev->data);

    event_set(&dev->event, dev->sock, EV_READ,
	    (void *)rpcap_read_len, (void *)dev);
    event_add(&dev->event, 0);
}

void 
rpcap_srv_init(char *data)
{
    char *tok, *host, *portstr, *iface;
    int   port;
    struct sockaddr_in inaddr;
    uint32_t addr;

    r_dev_t *rdev;

    tok = strtok(data, ":");

    if (!tok)
    {
	LOG("fmt: <host>:<iface>:<port>\n");
	exit(1);
    }

    host = tok;

    portstr = strtok(NULL, ":");

    if(!portstr)
    {
	LOG("No port in str %s\n", data);
	exit(1);
    }

    port = atoi(portstr);

    iface = strtok(NULL, ":");

    if(!iface)
    {
	LOG("No interface found in %s\n", data);
	exit(1);
    }

    if(!(rdev = calloc(sizeof(r_dev_t), 1)))
    {
	LOG("%s\n", strerror(errno));
	exit(1);
    }
    
    rdev->serv = strdup(host);
    rdev->iface = strdup(iface);
    rdev->port = port;

    addr = inet_addr(rdev->serv);
    inaddr.sin_family = AF_INET;
    inaddr.sin_addr.s_addr = addr;
    inaddr.sin_port = htons(rdev->port);

    if((rdev->sock = socket(PF_INET, SOCK_STREAM, 0)) <= 0)
    {
	LOG("%s\n", strerror(errno));
	exit(1);
    }

    if(connect(rdev->sock, (struct sockaddr *)&inaddr, 
		sizeof(inaddr)))
    {
	LOG("%s\n", strerror(errno));
	exit(1);
    }

    if (fcntl(rdev->sock, F_SETFL, 
		fcntl(rdev->sock, F_GETFL, 0) | O_NONBLOCK))
    {
	LOG("%s\n", strerror(errno));
	exit(1);
    }

    event_set(&rdev->event, rdev->sock, 
	    EV_WRITE, (void *)rpcap_handshake, rdev);
    event_add(&rdev->event, 0);
}

int
main(int argc, char **argv)
{

    int nargc;
    
    event_init();
    globals_init();
    tunfd = tuntap_init();

    if(!tunfd)
    {
	LOG("Unable to open up tuntap %s\n",
		strerror(errno));
	exit(1);
    }

    nargc = parse_args(argc, argv);

    while(nargc++ < argc-1)
    {
	printf("%s\n", argv[nargc]);
	rpcap_srv_init(argv[nargc]);
    }

    event_loop(0);

    return 0;
}
