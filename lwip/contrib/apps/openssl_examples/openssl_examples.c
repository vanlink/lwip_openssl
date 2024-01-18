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
    u16_t room;
    (void)arg;
    (void)err;

    room = altcp_sndbuf(tpcb);
    (void)room;

    altcp_write(tpcb, httpreq, strlen(httpreq), 0);
    altcp_output(tpcb);

    return ERR_OK;
}

static err_t cb_httpclient_sent(void *arg, struct altcp_pcb *tpcb, u16_t len)
{
    u16_t room;

    (void)arg;
    (void)tpcb;
    (void)len;

    room = altcp_sndbuf(tpcb);
    (void)room;

    return ERR_OK;
}

static err_t cb_httpclient_recv(void *arg, struct altcp_pcb *tpcb, struct pbuf *p, err_t err)
{
    struct pbuf *pcurr;
    char buff[2048];

    (void)arg;

    if(err != ERR_OK || !p){
        if(p){
            pbuf_free(p);
        }
        return ERR_ABRT;
    }

    pcurr = p;
    while(pcurr){
        snprintf(buff, sizeof(buff), "%s", (char *)pcurr->payload);
        buff[pcurr->len] = 0;
        printf("%s\n", buff);
        pcurr = pcurr->next;
    }

    altcp_recved(tpcb, p->tot_len);
    pbuf_free(p);

    return ERR_OK;
}

static err_t cb_httpserver_sent(void *arg, struct altcp_pcb *tpcb, u16_t len)
{
    u16_t room;

    (void)arg;
    (void)tpcb;
    (void)len;

    room = altcp_sndbuf(tpcb);
    (void)room;

    return ERR_OK;
}

static const char *httprsp = "HTTP/1.1 200 OK\r\nServer: lwip-openssl\r\nContent-length: 24\r\n\r\n<html>hello,world</html>";

static err_t cb_httpserver_recv(void *arg, struct altcp_pcb *tpcb, struct pbuf *p, err_t err)
{
    struct pbuf *pcurr;
    char buff[2048];

    (void)arg;

    if(err != ERR_OK || !p){
        if(p){
            pbuf_free(p);
        }
        altcp_close(tpcb);
        return ERR_OK;
    }

    pcurr = p;
    while(pcurr){
        snprintf(buff, sizeof(buff), "%s", (char *)pcurr->payload);
        buff[pcurr->len] = 0;
        printf("%s\n", buff);
        pcurr = pcurr->next;
    }

    altcp_recved(tpcb, p->tot_len);
    pbuf_free(p);

    altcp_write(tpcb, httprsp, strlen(httprsp), 0);
    altcp_output(tpcb);

    altcp_close(tpcb);

    return ERR_OK;
}

static err_t cb_httpserver_accept(void *arg, struct altcp_pcb *pcb, err_t err)
{
    (void)arg;
    (void)err;

    altcp_sent(pcb, cb_httpserver_sent);
    altcp_recv(pcb, cb_httpserver_recv);
    altcp_poll(pcb, NULL, 2U);

    return ERR_OK;
}

static void openssl_example_test_client(void *arg)
{
    struct altcp_pcb *newpcb = NULL;
    err_t err;
    ip_addr_t remote_addr;
    struct altcp_tls_config *conf = altcp_tls_create_config_client(NULL, 0);

    (void)arg;

    printf("===== openssl_example_test_client Starts =====\n");
    sys_msleep(5000);

    printf("Sending... HTTPS GET /\n");
    LOCK_TCPIP_CORE();
    newpcb = altcp_tls_alloc(conf, IPADDR_TYPE_V4);
    UNLOCK_TCPIP_CORE();

    IP_ADDR4(&remote_addr, 192, 168, 1, 1);

    LOCK_TCPIP_CORE();
    altcp_sent(newpcb, cb_httpclient_sent);
    altcp_recv(newpcb, cb_httpclient_recv);
    UNLOCK_TCPIP_CORE();

    LOCK_TCPIP_CORE();
    err = altcp_connect(newpcb, &remote_addr, 443, cb_httpclient_connected);
    if (err != ERR_OK) {
    }
    UNLOCK_TCPIP_CORE();

    sys_msleep(5000);

    LOCK_TCPIP_CORE();
    altcp_close(newpcb);
    UNLOCK_TCPIP_CORE();

    printf("===== openssl_example_test_client End =====\n");

}

static void openssl_example_test_server(void *arg)
{
    struct altcp_tls_config *conf = altcp_tls_create_config_server_privkey_cert((const u8_t *)"../server.key", 0, NULL, 0, (const u8_t *)"../server.crt", 0);
    struct altcp_pcb *listenpcb;
    struct altcp_pcb *listenpcbnew;
    ip_addr_t bind_addr;

    (void)arg;

    LWIP_ASSERT("altcp_tls_create_config_server_privkey_cert failed", conf);

    printf("===== openssl_example_test_server Starts =====\n");

    LOCK_TCPIP_CORE();
    listenpcb = altcp_tls_alloc(conf, IPADDR_TYPE_V4);
    UNLOCK_TCPIP_CORE();

    IP_ADDR4(&bind_addr, 0, 0, 0, 0);

    LOCK_TCPIP_CORE();
    altcp_bind(listenpcb, &bind_addr, 443);
    UNLOCK_TCPIP_CORE();

    LOCK_TCPIP_CORE();
    listenpcbnew = altcp_listen(listenpcb);
    UNLOCK_TCPIP_CORE();

    LOCK_TCPIP_CORE();
    altcp_accept(listenpcbnew, cb_httpserver_accept);
    UNLOCK_TCPIP_CORE();

    printf("===== openssl_example_test_server End =====\n");
}

void openssl_examples_init(void)
{
    sys_thread_new("openssl_example_test_client", openssl_example_test_client, NULL, 0, 0);
    sys_thread_new("openssl_example_test_server", openssl_example_test_server, NULL, 0, 0);
}

