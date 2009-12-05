#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
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
#include "config.h"
#include "iov.h"
#include "rpcap.h"

void rpcap_read_len(int sock, short which, r_dev_t *dev);

int persist;
char *config;
int run_daemon;

void globals_init(void)
{
    config  = NULL;
    persist = 0;
    run_daemon = 0;
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
	"-c <config>:       Configuration file\n"
	"-p         :       Keep virtual interfaces persistant\n"
	"-d         :       Run as a daemon\n"
	"-h         :       This help.\n";

    while((c=getopt(argc, argv, "dhc:p")) != -1)
    {
	switch(c)
	{
	    case 'h':
		printf("Usage: %s [opts]\n%s\n", 
			argv[0], help);
		exit(1);
	    case 'p':
		persist = 1;
		break;
	    case 'c':
		config = optarg;
		break;
	    case 'd':
		run_daemon = 1;
		break;
	}
    }
    return argcret;
}

int
tuntap_init(char *iname)
{

    struct ifreq    ifr;
    int             fd,
                    err;
    int sock;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
	return fd;

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TAP|IFF_NO_PI;

    strncpy(ifr.ifr_name, iname, IFNAMSIZ);

    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
	close(fd);
	return err;
    }

    sock = socket(PF_UNIX, SOCK_STREAM, 0);
    ioctl(sock, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_UP;
    ioctl(sock, SIOCSIFFLAGS, &ifr);
    close(sock);

    if (persist)
	ioctl(fd, TUNSETPERSIST, 1);
    else
	ioctl(fd, TUNSETPERSIST, 0);

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

    if(write(dev->tunfd, dev->data.buf, dev->data.offset) <= 0)
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
	int flags = 0;

	bpfstr_len = dev->bpf?strlen(dev->bpf):0;
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
	memcpy(&dev->data.buf[5], &dev->snaplen, sizeof(uint16_t));
	memcpy(&dev->data.buf[7], &flags, sizeof(uint8_t)); 
	memcpy(&dev->data.buf[8], dev->iface, iface_len);

	if (dev->bpf)
	    memcpy(&dev->data.buf[8+iface_len], dev->bpf, bpfstr_len);
	
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

void rpdev_connect(r_dev_t *dev)
{
    struct sockaddr_in inaddr;
    uint32_t addr;

    addr = inet_addr(dev->serv);

    inaddr.sin_family      = AF_INET;
    inaddr.sin_addr.s_addr = addr; 
    inaddr.sin_port        = htons(dev->port);

    if ((dev->sock = socket(PF_INET, SOCK_STREAM, 0)) <= 0)
    {
	LOG("sockerr: %s\n", strerror(errno));
	exit(1);
    }

    if (connect(dev->sock, (struct sockaddr *)&inaddr,
		sizeof(inaddr)))
    {
	LOG("connerr: %s\n", strerror(errno));
	exit(1);
    }

    if (fcntl(dev->sock, F_SETFL,
		fcntl(dev->sock, F_GETFL, 0) | O_NONBLOCK))
    {
	LOG("fcntl: %s\n", strerror(errno));
	exit(1);
    }

    event_set(&dev->event, dev->sock,
	    EV_WRITE, (void *)rpcap_handshake, dev);
    event_add(&dev->event, 0);
}

void rpdev_init(r_dev_t *dev)
{
    rpdev_connect(dev);
    dev->tunfd = tuntap_init(dev->virtual_iface);
}

void 
connections_init(r_dev_list_t *rdev_list)
{
    r_dev_lnode_t *lnode;

    lnode = rdev_list->head;

    while(lnode)
    {
	r_dev_t *dev;
	dev = lnode->dev; 
	rpdev_init(dev);
	lnode = lnode->next;
    }
}

void
daemonize(const char *path)
{
    int             status;
    int             fd;  

    status = fork();
    if (status < 0) { 
        fprintf(stderr, "Can't fork!\n");
        exit(1);
    }    

    else if (status > 0) 
        _exit(0);

#if HAVE_SETSID
    assert(setsid() >= 0);
#elif defined(TIOCNOTTY)
    fd = open("/dev/tty", O_RDWR);

    if (fd >= 0)
        assert(ioctl(fd, TIOCNOTTY, NULL) >= 0);
#endif

    assert(chdir(path) >= 0);

    fd = open("/dev/null", O_RDWR, 0);

    if (fd != -1) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > 2) 
            close(fd);
    }    
}
    
int
main(int argc, char **argv)
{

    r_dev_list_t *rdev_list;

    globals_init();
    parse_args(argc, argv);
    rdev_list = config_parse(config);
    event_init();
    connections_init(rdev_list);

    if (run_daemon)
	daemonize("/tmp");

    event_loop(0);
    return 0;
}
