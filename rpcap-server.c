#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <event.h>
#include <pcap.h>

#include "iov.h"
#include "rpcap.h"

#define MAX_DEV_LEN 255
#define MAX_BPF_LEN 0xFFFFFFFF

typedef struct rp_start_header {
    uint8_t         dev_sz;
    uint32_t        bpf_sz;
    uint16_t        snaplen;
    uint8_t         opts;
    char           *dev;
    char           *bpf;
} rp_start_header_t;

typedef struct client_conn {
    int             sock;
    iov_t           data;
    rp_start_header_t start_header;
    struct event    event;
    struct event    pcap_event;
    int             pcap_fd;
    pcap_t         *descr;
} client_conn_t;

static uint16_t listen_port;
static char    *bind_addr;
static struct event server_event;

void
globals_init(void)
{
    listen_port = 1025;
    bind_addr = "0.0.0.0";
}

void
print_help(char **argv)
{
    printf("Usage %s [opts]\n"
	   "-p <port>:    Listen Port\n" "-h       :    Help\n", argv[0]);
    return;
}

int
parse_args(int argc, char **argv)
{
    int             c;

    while ((c = getopt(argc, argv, "b:hp:")) != -1) {
	switch (c) {
	case 'b':
	    bind_addr = optarg;
	    break;
	case 'p':
	    listen_port = atoi(optarg);
	    break;
	case 'h':
	    print_help(argv);
	default:
	    exit(1);
	}
    }
    return 0;
}

void
free_client_conn(client_conn_t * conn)
{
    reset_iov(&conn->data);

    event_del(&conn->event);
    event_del(&conn->pcap_event);

    close(conn->sock);
    close(conn->pcap_fd);

    if (conn->start_header.dev)
	free(conn->start_header.dev);
    if (conn->start_header.bpf)
	free(conn->start_header.bpf);
    if (conn->descr)
	pcap_close(conn->descr);

    free(conn);
}

void
pcap_write(int sock, short which, client_conn_t * conn)
{
    int             ioret;

    ioret = write_iov(&conn->data, conn->sock);

    if (ioret < 0) {
	free_client_conn(conn);
	return;
    }

    if (ioret > 0) {
	event_set(&conn->event, sock, EV_WRITE,
		  (void *) pcap_write, (void *) conn);
	event_add(&conn->event, 0);
	return;
    }

    reset_iov(&conn->data);
    return;
}

void
pcap_write_init(client_conn_t * conn,
		const struct pcap_pkthdr *hdr, unsigned char *pkt)
{
    if (!conn->data.buf)
	initialize_iov(&conn->data, sizeof(uint32_t) + hdr->caplen);

    memcpy(conn->data.buf, &hdr->caplen, sizeof(uint32_t));

    memcpy(&conn->data.buf[sizeof(uint32_t)], pkt, hdr->caplen);

    event_set(&conn->event, conn->sock,
	      EV_WRITE, (void *) pcap_write, (void *) conn);
    event_add(&conn->event, 0);
}

void
pcap_driver(int sock, short which, client_conn_t * conn)
{
    /*
     * is there data on the buffer? If so, continue on 
     */
    if (conn->data.buf)
	return;

    pcap_dispatch(conn->descr, 1, (void *) pcap_write_init, (void *) conn);
}

void
pcap_event_init(client_conn_t * conn)
{
    struct bpf_program filterp;
    bpf_u_int32     maskp,
                    netp;
    char            errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_lookupnet(conn->start_header.dev, &netp, &maskp, errbuf) < 0)
	goto pcap_err;

    if ((conn->descr =
	 pcap_open_live(conn->start_header.dev,
			conn->start_header.snaplen, 1, 100,
			errbuf)) == NULL)
	goto pcap_err;

    if (conn->start_header.bpf != NULL) {
	if (pcap_compile(conn->descr, &filterp,
			 conn->start_header.bpf, 0, netp) < 0)
	    goto pcap_err;

	pcap_setfilter(conn->descr, &filterp);
    }

    if (pcap_setnonblock(conn->descr, 1, errbuf) < 0)
	goto pcap_err;

    if ((conn->pcap_fd = pcap_get_selectable_fd(conn->descr)) <= 0)
	goto pcap_err;

    event_set(&conn->pcap_event, conn->pcap_fd,
	      EV_READ | EV_PERSIST, (void *) pcap_driver, (void *) conn);
    event_add(&conn->pcap_event, 0);
    return;

  pcap_err:
    LOG("pcap err %s\n", errbuf);
    free_client_conn(conn);
    return;
}


void
client_read_hdr_data(int sock, short which, client_conn_t * conn)
{
    int             ioret;

    if (!conn->data.buf)
	initialize_iov(&conn->data,
		       conn->start_header.dev_sz +
		       conn->start_header.bpf_sz);

    ioret = read_iov(&conn->data, sock);

    if (ioret < 0) {
	LOG("sockerr %s\n", strerror(errno));
	free_client_conn(conn);
	return;
    }

    if (ioret > 0) {
	event_set(&conn->event, sock, EV_READ,
		  (void *) client_read_hdr_data, conn);
	event_add(&conn->event, 0);
	return;
    }

    if (conn->start_header.dev_sz)
	conn->start_header.dev = calloc(conn->start_header.dev_sz + 1, 1);

    if (conn->start_header.dev_sz && !conn->start_header.dev) {
	LOG("alloc err %s\n", strerror(errno));
	exit(1);
    }

    if (conn->start_header.bpf_sz)
	conn->start_header.bpf = calloc(conn->start_header.bpf_sz + 1, 1);

    if (conn->start_header.bpf_sz && !conn->start_header.bpf) {
	LOG("alloc err %s\n", strerror(errno));
	exit(1);
    }

    if (conn->start_header.dev_sz)
	memcpy(conn->start_header.dev, conn->data.buf,
	       conn->start_header.dev_sz);

    if (conn->start_header.bpf_sz)
	memcpy(conn->start_header.bpf,
	       &conn->data.buf[conn->start_header.dev_sz],
	       conn->start_header.bpf_sz);

    LOG("BPF %s\n", conn->start_header.bpf);
    LOG("DEV %s\n", conn->start_header.dev);

    reset_iov(&conn->data);
    pcap_event_init(conn);

    return;
}

void
client_read_hdr(int sock, short which, client_conn_t * conn)
{
    int             ioret;

    if (!conn->data.buf)
	initialize_iov(&conn->data,
		       /*
		        * device str len 
		        */
		       sizeof(uint8_t) +
		       /*
		        * bpf string len 
		        */
		       sizeof(uint32_t) +
		       /*
		        * pcap snaplen 
		        */
		       sizeof(uint16_t) +
		       /*
		        * opts 
		        */
		       sizeof(uint8_t));

    ioret = read_iov(&conn->data, sock);

    if (ioret < 0) {
	/*
	 * sockerr 
	 */
	LOG("sockerr %s\n", strerror(errno));
	free_client_conn(conn);
	close(sock);
	return;
    }

    if (ioret > 0) {
	/*
	 * continue reading header 
	 */
	event_set(&conn->event, sock, EV_READ, (void *) client_read_hdr,
		  conn);
	event_add(&conn->event, 0);
	return;
    }

    memcpy(&conn->start_header.dev_sz, &conn->data.buf[0],
	   sizeof(uint8_t));
    memcpy(&conn->start_header.bpf_sz, &conn->data.buf[1],
	   sizeof(uint32_t));
    memcpy(&conn->start_header.snaplen, &conn->data.buf[5],
	   sizeof(uint16_t));
    memcpy(&conn->start_header.opts, &conn->data.buf[7], sizeof(uint8_t));

    if (conn->start_header.dev_sz > MAX_DEV_LEN) {
	free_client_conn(conn);
	return;
    }

    if (conn->start_header.bpf_sz > MAX_BPF_LEN) {
	free_client_conn(conn);
	return;
    }

    LOG("total = %d\n", conn->start_header.dev_sz +
	    conn->start_header.bpf_sz);
    LOG("dev_sz = %d\n", conn->start_header.dev_sz);
    LOG("bpf_sz = %d\n", conn->start_header.bpf_sz);
    LOG("snaplen = %d\n", conn->start_header.snaplen);
    LOG("opts = %d\n", conn->start_header.opts);

    event_set(&conn->event, sock, EV_READ,
	      (void *) client_read_hdr_data, conn);
    event_add(&conn->event, 0);

    reset_iov(&conn->data);

    return;
}

void
server_driver(int sock, short which, void *args)
{
    int             csock;
    struct sockaddr_in addr;
    socklen_t       addrlen;
    client_conn_t  *new_conn;

    addrlen = sizeof(struct sockaddr);

    csock = accept(sock, (struct sockaddr *) &addr, &addrlen);

    if (csock < 0) {
	close(csock);
	return;
    }

    if (fcntl(csock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK)) {
	close(csock);
	return;
    }

    if (!(new_conn = calloc(sizeof(client_conn_t), 1))) {
	LOG("Could not allocate memory %s", strerror(errno));
	exit(1);
    }

    LOG("New sock is %d\n", csock);

    new_conn->sock = csock;
    event_set(&new_conn->event, csock, EV_READ,
	      (void *) client_read_hdr, new_conn);
    event_add(&new_conn->event, 0);

    return;
}

int
server_init(void)
{
    struct sockaddr_in addr;
    int             sock,
                    v = 1;

    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) <= 0)
	return -1;

    if ((setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
		    (char *) &v, sizeof((v)))) < 0)
	return -1;

    if (fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK))
	return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(listen_port);
    addr.sin_addr.s_addr = inet_addr(bind_addr);

    if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0)
	return -1;

    if (listen(sock, 1024) < 0)
	return -1;

    event_set(&server_event, sock, EV_READ | EV_PERSIST, server_driver,
	      NULL);
    event_add(&server_event, 0);

    return 0;
}

int
main(int argc, char **argv)
{
    globals_init();
    parse_args(argc, argv);
    event_init();
    server_init();
    event_loop(0);

    return 0;
}
