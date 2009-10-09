#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <event.h>
#include "iov.h"


typedef struct r_dev {
  int tunfd;
	int sock;
  int snaplen;
	char *serv;
	char *iface;
  char *virtual_iface;
  char *bpf;
	unsigned short port;
	iov_t data;
	struct event event;
} r_dev_t;

typedef struct r_dev_lnode {
	r_dev_t *dev;
	struct r_dev_lnode *next;
} r_dev_lnode_t;

typedef struct r_dev_list {
	r_dev_lnode_t *head;
	uint32_t nnodes;
} r_dev_list_t;	

r_dev_t *rdev_init(void);
r_dev_lnode_t *rdev_lnode_init(r_dev_t *);
r_dev_list_t *rdev_list_init(void);
r_dev_list_t *rdev_list_add(r_dev_list_t *, r_dev_t *);
r_dev_list_t *config_parse(char *filename);
