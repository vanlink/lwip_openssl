#include "lwip/opt.h"
#include "lwip/sys.h"

#if LWIP_ALTCP
#if LWIP_ALTCP_TLS

#include "lwip/altcp.h"
#include "lwip/altcp_tls.h"
#include "lwip/priv/altcp_priv.h"

#include <string.h>

#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ocsp.h>
#include <openssl/bn.h>
#include <openssl/async.h>

struct altcp_tls_config {
    SSL_CTX *openssl_ctx;
};

typedef struct altcp_openssl_state_s {
    SSL *openssl_ssl;
    u8_t handshake_done;
} altcp_openssl_state_t;

struct altcp_tls_config *altcp_tls_create_config_client(const u8_t *ca, size_t ca_len)
{
    struct altcp_tls_config *conf;

    (void)ca;
    (void)ca_len;

    conf = (struct altcp_tls_config *)calloc(1, sizeof(struct altcp_tls_config));

    if(!conf){
        return NULL;
    }

    conf->openssl_ctx = SSL_CTX_new(TLS_client_method());

    if(!conf->openssl_ctx){
        free(conf);
        return NULL;
    }
/*
    SSL_CTX_set_max_proto_version(conf->openssl_ctx, TLS1_2_VERSION);
*/
    SSL_CTX_set_verify(conf->openssl_ctx, SSL_VERIFY_NONE, NULL);

    SSL_CTX_set_session_cache_mode(conf->openssl_ctx, SSL_SESS_CACHE_OFF);

    return conf;
}

void altcp_tls_free_config(struct altcp_tls_config *conf)
{
    if(!conf){
        return;
    }

    if(conf->openssl_ctx){
        SSL_CTX_free(conf->openssl_ctx);
    }

    free(conf);
}

static int get_data_from_ssl(SSL *ssl, char *buff, int buff_len)
{
    BIO *wbio;
    int ret = 0;

    if(!buff || !buff_len){
        return 0;
    }

    wbio = SSL_get_wbio(ssl);
    if(!wbio){
        return -1;
    }

    if(BIO_pending(wbio) > 0){
        ret = BIO_read(wbio, buff, buff_len);
    }

    return ret;
}

static int put_data_into_ssl(SSL *ssl, const char *data, int data_len)
{
    BIO *rbio;
    int ret;

    if(!data || !data_len){
        return 0;
    }

    rbio = SSL_get_rbio(ssl);
    if(!rbio){
        return -1;
    }

    ret = BIO_write(rbio, data, data_len);

    LWIP_ASSERT("put_data_into_ssl fail", data_len == ret);

    return ret;
}

static int do_handshake_process(SSL *ssl)
{
    int ret, error;

    ret = SSL_do_handshake(ssl);
    error = SSL_get_error(ssl, ret);

    return (error == SSL_ERROR_NONE) ? 0 : -1;
}

static int get_data_from_ssl_and_send_out(SSL *ssl, struct altcp_pcb *inner_conn)
{
    char buff[4096];
    unsigned int room;
    int ret, sum = 0;
    err_t err;

    while(1){

        room = altcp_sndbuf(inner_conn);

        if(room < 1){
            return sum;
        }

        ret = get_data_from_ssl(ssl, buff, room < sizeof(buff) ? room : sizeof(buff));
        if(ret < 1){
            return sum;
        }
        sum += ret;

        err = altcp_write(inner_conn, buff, ret, 0);
        if (err !=  ERR_OK) {
            return sum;
        }

        err = altcp_output(inner_conn);
        if (err !=  ERR_OK) {
            return sum;
        }
    }

    return sum;
}

static err_t altcp_openssl_lower_connected(void *arg, struct altcp_pcb *inner_conn, err_t err)
{
    struct altcp_pcb *conn = (struct altcp_pcb *)arg;
    altcp_openssl_state_t *state;

    (void)err;

    if(!conn || !conn->state){
        return ERR_VAL;
    }

    state = (altcp_openssl_state_t *)conn->state;

    do_handshake_process(state->openssl_ssl);

    get_data_from_ssl_and_send_out(state->openssl_ssl, inner_conn);

    return ERR_OK;
}


static err_t altcp_openssl_lower_recv(void *arg, struct altcp_pcb *inner_conn, struct pbuf *p, err_t err)
{
    struct altcp_pcb *conn = (struct altcp_pcb *)arg;
    altcp_openssl_state_t *state;
    struct pbuf *pcurr;
    int ret, error;
    err_t err2 = ERR_OK;
    struct pbuf *buf;
    int buff_len = 4096;

    if(err != ERR_OK || !p){
        if(p){
            pbuf_free(p);
        }
        return ERR_ABRT;
    }

    if(!conn || !conn->state){
        err2 = ERR_ABRT;
        goto exit;
    }

    state = (altcp_openssl_state_t *)conn->state;

    pcurr = p;
    while(pcurr){
        put_data_into_ssl(state->openssl_ssl, (const char *)pcurr->payload, pcurr->len);
        pcurr = pcurr->next;
    }

    if(state->handshake_done){

        while(1){
            buf = pbuf_alloc(PBUF_RAW, buff_len, PBUF_RAM);
            if(!buf){
                err2 = ERR_ABRT;
                break;
            }
            ret = SSL_read(state->openssl_ssl, buf->payload, buff_len);
            error = SSL_get_error(state->openssl_ssl, ret);
            (void)error;
            if(ret > 0){
                pbuf_realloc(buf, ret);
                if (conn->recv) {
                    err2 = conn->recv(conn->arg, conn, buf, ERR_OK);
                }else{
                    pbuf_free(buf);
                }
            }else{
                pbuf_free(buf);
                break;
            }
        }

    }else{
        ret = do_handshake_process(state->openssl_ssl);
        get_data_from_ssl_and_send_out(state->openssl_ssl, inner_conn);
        if(ret >= 0){
            state->handshake_done = 1;
            if(conn->connected){
                err2 = conn->connected(conn->arg, conn, ERR_OK);
            }
        }
    }

exit:

    altcp_recved(inner_conn, p->tot_len);
    pbuf_free(p);

    return err2;
}

static err_t altcp_openssl_lower_sent(void *arg, struct altcp_pcb *inner_conn, u16_t len)
{
    struct altcp_pcb *conn = (struct altcp_pcb *)arg;
    altcp_openssl_state_t *state = (altcp_openssl_state_t *)conn->state;

    get_data_from_ssl_and_send_out(state->openssl_ssl, inner_conn);

    if (conn->sent && state->handshake_done){
        return conn->sent(conn->arg, conn, len);
    }

    return ERR_OK;
}

static void altcp_openssl_lower_err(void *arg, err_t err)
{
  struct altcp_pcb *conn = (struct altcp_pcb *)arg;
  if (conn) {
    conn->inner_conn = NULL;
    if (conn->err) {
      conn->err(conn->arg, err);
    }
    altcp_free(conn);
  }
}

static err_t altcp_openssl_connect(struct altcp_pcb *conn, const ip_addr_t *ipaddr, u16_t port, altcp_connected_fn connected)
{
  if (conn == NULL) {
    return ERR_VAL;
  }
  conn->connected = connected;
  return altcp_connect(conn->inner_conn, ipaddr, port, altcp_openssl_lower_connected);
}

static void altcp_openssl_dealloc(struct altcp_pcb *conn)
{
  if (conn) {
    altcp_openssl_state_t *state = (altcp_openssl_state_t *)conn->state;
    if (state) {
      if(state->openssl_ssl){
        SSL_free(state->openssl_ssl);
        state->openssl_ssl = NULL;
      }
      free(state);
      conn->state = NULL;
    }
  }
}

static err_t altcp_openssl_write(struct altcp_pcb *conn, const void *dataptr, u16_t len, u8_t apiflags)
{
    altcp_openssl_state_t *state;
    struct altcp_pcb *inner_conn = conn->inner_conn;

    LWIP_UNUSED_ARG(apiflags);

    state = (altcp_openssl_state_t *)conn->state;

    if(!state->handshake_done){
        return ERR_ABRT;
    }

    SSL_write(state->openssl_ssl, dataptr, len);

    get_data_from_ssl_and_send_out(state->openssl_ssl, inner_conn);

    return ERR_OK;
}

static void altcp_openssl_recved(struct altcp_pcb *conn, u16_t len)
{
    (void)conn;
    (void)len;
}

static void altcp_openssl_setup_callbacks(struct altcp_pcb *conn, struct altcp_pcb *inner_conn)
{
  altcp_arg(inner_conn, conn);
  altcp_recv(inner_conn, altcp_openssl_lower_recv);
  altcp_sent(inner_conn, altcp_openssl_lower_sent);
  altcp_err(inner_conn, altcp_openssl_lower_err);
}

static void altcp_openssl_remove_callbacks(struct altcp_pcb *inner_conn)
{
  altcp_arg(inner_conn, NULL);
  altcp_recv(inner_conn, NULL);
  altcp_sent(inner_conn, NULL);
  altcp_err(inner_conn, NULL);
  altcp_poll(inner_conn, NULL, inner_conn->pollinterval);
}

static err_t altcp_openssl_close(struct altcp_pcb *conn)
{
  struct altcp_pcb *inner_conn;
  if (conn == NULL) {
    return ERR_VAL;
  }
  inner_conn = conn->inner_conn;
  if (inner_conn) {
    err_t err;
    altcp_openssl_remove_callbacks(conn->inner_conn);
    err = altcp_close(conn->inner_conn);
    if (err != ERR_OK) {
      altcp_openssl_setup_callbacks(conn, inner_conn);
      return err;
    }
    conn->inner_conn = NULL;
  }
  altcp_free(conn);
  return ERR_OK;
}

static void altcp_openssl_abort(struct altcp_pcb *conn)
{
  if (conn != NULL) {
    altcp_abort(conn->inner_conn);
  }
}

static u16_t altcp_openssl_mss(struct altcp_pcb *conn)
{
  if (conn == NULL) {
    return 0;
  }
  return altcp_mss(conn->inner_conn);
}

static u16_t altcp_openssl_sndbuf(struct altcp_pcb *conn)
{
    altcp_openssl_state_t *state;
    u16_t sndbuf;

    if(!conn) {
        return 0;
    }

    state = (altcp_openssl_state_t *) conn->state;
    if(!state || !state->handshake_done) {
        return 0;
    }

    if(!conn->inner_conn) {
        return 0;
    }

    sndbuf = altcp_sndbuf(conn->inner_conn);

    if(sndbuf > 32){
        sndbuf -= 32;
    }else{
        sndbuf = 0;
    }

    return sndbuf;
}

static const struct altcp_functions altcp_openssl_functions = {
  altcp_default_set_poll,
  altcp_openssl_recved,
  altcp_default_bind,
  altcp_openssl_connect,
  NULL,
  altcp_openssl_abort,
  altcp_openssl_close,
  altcp_default_shutdown,
  altcp_openssl_write,
  altcp_default_output,
  altcp_openssl_mss,
  altcp_openssl_sndbuf,
  altcp_default_sndqueuelen,
  altcp_default_nagle_disable,
  altcp_default_nagle_enable,
  altcp_default_nagle_disabled,
  altcp_default_setprio,
  altcp_openssl_dealloc,
  altcp_default_get_tcp_addrinfo,
  altcp_default_get_ip,
  altcp_default_get_port,
#if LWIP_TCP_KEEPALIVE
  altcp_default_keepalive_disable,
  altcp_default_keepalive_enable,
#endif
#ifdef LWIP_DEBUG
  altcp_default_dbg_get_tcp_state,
#endif
};

static err_t altcp_openssl_setup(void *conf, struct altcp_pcb *conn, struct altcp_pcb *inner_conn)
{
    struct altcp_tls_config *config;
    altcp_openssl_state_t *state;
    BIO *rbio = NULL;
    BIO *wbio = NULL;

    if (!conf) {
        return ERR_ARG;
    }

    config = (struct altcp_tls_config *)conf;

    if (!config->openssl_ctx) {
        return ERR_ARG;
    }

    state = (altcp_openssl_state_t *)calloc(1, sizeof(altcp_openssl_state_t));
    if(!state){
        goto err;
    }
    conn->state = state;

    rbio = BIO_new(BIO_s_mem());
    if(!rbio){
        goto err;
    }
    wbio = BIO_new(BIO_s_mem());
    if(!wbio){
        goto err;
    }

    BIO_set_nbio(rbio, 1);
    BIO_set_nbio(wbio, 1);

    state->openssl_ssl = SSL_new(config->openssl_ctx);
    if(!state->openssl_ssl){
        goto err;
    }

    SSL_set_connect_state(state->openssl_ssl);
    SSL_set_bio(state->openssl_ssl, rbio, wbio);

    altcp_openssl_setup_callbacks(conn, inner_conn);

    conn->inner_conn = inner_conn;
    conn->fns = &altcp_openssl_functions;

    return ERR_OK;

err:

    if(rbio){
        BIO_free(rbio);
    }
    if(wbio){
        BIO_free(wbio);
    }

    return ERR_ABRT;
}

struct altcp_pcb *altcp_tls_wrap(struct altcp_tls_config *config, struct altcp_pcb *inner_pcb)
{
    struct altcp_pcb *ret;
    if (inner_pcb == NULL) {
        return NULL;
    }
    ret = altcp_alloc();
    if (ret != NULL) {
        if (altcp_openssl_setup(config, ret, inner_pcb) != ERR_OK) {
            altcp_free(ret);
            return NULL;
        }
    }
    return ret;
}

#endif
#endif

