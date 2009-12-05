#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <confuse.h>
#include "config.h"


r_dev_t *rdev_init(void)
{
    return 
	(r_dev_t *)calloc(sizeof(r_dev_t), 1);
}

r_dev_lnode_t *rdev_lnode_init(r_dev_t *dev)
{
    r_dev_lnode_t *lnode;

    lnode = malloc(sizeof(r_dev_lnode_t));
    lnode->dev = dev;
    lnode->next = NULL;
    return lnode;
}

r_dev_list_t *rdev_list_init(void)
{
    return (r_dev_list_t *)calloc(sizeof(r_dev_list_t),1);
}

r_dev_list_t *rdev_list_add(
	r_dev_list_t *list,
       	r_dev_t *dev)
{
    r_dev_lnode_t *lnode;

    if (!list|| !dev)
	return NULL;

    if (!(lnode = rdev_lnode_init(dev)))
	return NULL;

    lnode->next = list->head;
    list->head  = lnode;
    list->nnodes++;
    return list;
}
	
r_dev_list_t *config_parse(char *filename)
{
   cfg_t *cfg;
   r_dev_list_t *list; 
   unsigned int i;

   if (!filename)
       filename = "rpcap.conf";

   cfg = NULL;
   
   if(!(list = rdev_list_init()))
       return NULL;

   cfg_opt_t server_opts[] = {
       CFG_STR("output-dev", "rpcap0", CFGF_NONE),
       CFG_STR("bpf", NULL, CFGF_NONE),
       CFG_INT("snaplen", 512, CFGF_NONE),
       CFG_INT("compression-level", 0, CFGF_NONE),
       CFG_INT("server-port", 1025, CFGF_NONE),
       CFG_STR("interface", "eth0", CFGF_NONE),
       CFG_STR("server", NULL, CFGF_NONE),
       CFG_BOOL("ignore-rpcap-traffic", 0, CFGF_NONE),
       CFG_END()
   };

   cfg_opt_t opts[] = {
       CFG_SEC("rpcap", server_opts, CFGF_MULTI | CFGF_TITLE),
       CFG_END()
   };

   cfg = cfg_init(opts, CFGF_NOCASE);

   if (cfg_parse(cfg, filename) == CFG_PARSE_ERROR)
   {
       cfg_free(cfg);
       exit(1);
   }

   for (i = 0; i < cfg_size(cfg, "rpcap"); i++)
   {
       cfg_t *rule;
       r_dev_t *dev;
       char *bpf;
       int no_rp_traf = 0;

       bpf = NULL;
       dev = rdev_init();
       rule = cfg_getnsec(cfg, "rpcap", i);

       if (!cfg_getstr(rule, "server"))
       {
	   fprintf(stderr, "No server found in rule %s\n",
		   cfg_title(rule));
	   exit(1);
       }

       if((bpf = cfg_getstr(rule, "bpf")))
	   dev->iface   = strdup(bpf);

       dev->iface   = strdup(cfg_getstr(rule, "interface"));
       dev->port    = cfg_getint(rule, "server-port");
       dev->serv    = strdup(cfg_getstr(rule, "server"));
       dev->snaplen = cfg_getint(rule, "snaplen");
       dev->virtual_iface = strdup(cfg_getstr(rule, "output-dev"));

       no_rp_traf = cfg_getbool(rule, "ignore-rpcap-traffic");

       rdev_list_add(list, dev);

   
       if (no_rp_traf)
       {
	   char mbuf[2048];

	   memset(mbuf, 0, sizeof(mbuf));

	   snprintf(mbuf, sizeof(mbuf)-1, 
	       "(!(host %s && port %d)) %s %s", 
	       dev->serv, dev->port, dev->bpf?"&&":"",
	       dev->bpf?dev->bpf:"");

	   free(dev->bpf);
	   dev->bpf = strdup(mbuf);
       }
   }
   cfg_free(cfg);
   return list;
}


#ifdef TEST_CONFIG
int main(int argc, char **argv)
{
    r_dev_list_t *rdev_list;

    rdev_list = config_parse(NULL);

    return 0;
}
#endif

