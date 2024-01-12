#include "openssl_examples.h"

#include "lwip/opt.h"

#include "lwip/sys.h"
#include "lwip/altcp.h"
#include "lwip/altcp_tls.h"

#include <string.h>
#include <stdio.h>

static const char *httpreq = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";

static inline err_t cb_httpclient_connected(void *arg, struct altcp_pcb *tpcb, err_t err)
{
    (void)arg;
    (void)err;

    altcp_write(tpcb, httpreq, strlen(httpreq), 0);
    altcp_output(tpcb);

    return ERR_OK;
}

static err_t cb_httpclient_sent(void *arg, struct altcp_pcb *tpcb, u16_t len)
{
    (void)arg;
    (void)tpcb;
    (void)len;
    
    return ERR_OK;
}

static err_t cb_httpclient_recv(void *arg, struct altcp_pcb *tpcb, struct pbuf *p, err_t err)
{
    struct pbuf *pcurr;

    (void)arg;

    if(err != ERR_OK || !p){
        if(p){
            pbuf_free(p);
        }
        return ERR_ABRT;
    }

    printf("\n---S----\n");
    pcurr = p;
    while(pcurr){
        printf("\n---ss----\n");
        printf("%s\n", (char *)pcurr->payload);
        printf("\n---ee----\n");
        pcurr = pcurr->next;
    }
    printf("\n---E----\n");

    altcp_recved(tpcb, p->tot_len);
    pbuf_free(p);

    return ERR_OK;
}

void openssl_examples_init(void)
{
    struct altcp_pcb *newpcb = NULL;
    err_t err;
    ip_addr_t remote_addr;
    struct altcp_tls_config *conf = altcp_tls_create_config_client(NULL, 0);

    (void)conf;
    /*
    newpcb = altcp_new(NULL);
    */
    newpcb = altcp_tls_alloc(conf, IPADDR_TYPE_V4);
    
    IP_ADDR4(&remote_addr, 192, 168, 1, 1);

    altcp_sent(newpcb, cb_httpclient_sent);
    altcp_recv(newpcb, cb_httpclient_recv);

    err = altcp_connect(newpcb, &remote_addr, 443, cb_httpclient_connected);
    if (err != ERR_OK) {
    }
}

