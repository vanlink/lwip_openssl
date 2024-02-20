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

    u8_t openssl_is_server;
};

typedef struct altcp_openssl_state_s {
    void *openssl_conf;
    SSL *openssl_ssl;
    u8_t handshake_done;
    u8_t ssl_is_server;
} altcp_openssl_state_t;

static err_t altcp_openssl_setup(void *conf, struct altcp_pcb *conn, struct altcp_pcb *inner_conn);

struct altcp_tls_config *altcp_tls_create_config_client(const u8_t *ca, size_t ca_len)
{
    struct altcp_tls_config *conf;

    (void)ca;
    (void)ca_len;

    printf("\n===== LwIP with openssl %s =====\n", OpenSSL_version(OPENSSL_VERSION));

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

struct altcp_tls_config *altcp_tls_create_config_server_privkey_cert(const u8_t *privkey, size_t privkey_len, const u8_t *privkey_pass, size_t privkey_pass_len,
                                                                                        const u8_t *cert, size_t cert_len)
{
    struct altcp_tls_config *conf = (struct altcp_tls_config *)calloc(1, sizeof(struct altcp_tls_config));

    (void)privkey_len;
    (void)privkey_pass;
    (void)privkey_pass_len;
    (void)cert_len;

    if(!conf){
        goto error;
    }

    conf->openssl_is_server = 1;

    conf->openssl_ctx = SSL_CTX_new(TLS_server_method());

    if(!conf->openssl_ctx){
        goto error;
    }

    if(SSL_CTX_use_certificate_file(conf->openssl_ctx, (const char *)cert, SSL_FILETYPE_PEM) <= 0){
        goto error;
    }

    if(SSL_CTX_use_PrivateKey_file(conf->openssl_ctx, (const char *)privkey, SSL_FILETYPE_PEM) <= 0){
        goto error;
    }

    if(!SSL_CTX_check_private_key(conf->openssl_ctx)){
        goto error;
    }
/*
    SSL_CTX_set_max_proto_version(conf->openssl_ctx, TLS1_2_VERSION);
*/
    SSL_CTX_set_session_cache_mode(conf->openssl_ctx, SSL_SESS_CACHE_OFF);

    return conf;

error:

    if(conf){
        if(conf->openssl_ctx){
            SSL_CTX_free(conf->openssl_ctx);
        }
        free(conf);
    }

    return NULL;
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

        err = altcp_write(inner_conn, buff, ret, TCP_WRITE_FLAG_COPY);
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

static SSL *create_openssl_ssl(SSL_CTX *ctx, int is_server)
{
    SSL *ssl = NULL;
    BIO *rbio = NULL;
    BIO *wbio = NULL;

    rbio = BIO_new(BIO_s_mem());
    if(!rbio){
        goto error;
    }
    wbio = BIO_new(BIO_s_mem());
    if(!wbio){
        goto error;
    }

    BIO_set_nbio(rbio, 1);
    BIO_set_nbio(wbio, 1);

    ssl = SSL_new(ctx);
    if(!ssl){
        goto error;
    }

    if(is_server){
        SSL_set_accept_state(ssl);
    }else{
        SSL_set_connect_state(ssl);
    }
    
    SSL_set_bio(ssl, rbio, wbio);

    return ssl;

error:

    if(rbio){
        BIO_free(rbio);
    }
    if(wbio){
        BIO_free(wbio);
    }

    return NULL;
}

static err_t altcp_openssl_lower_connected(void *arg, struct altcp_pcb *inner_conn, err_t err)
{
    struct altcp_pcb *conn = (struct altcp_pcb *)arg;
    altcp_openssl_state_t *state;
    struct altcp_tls_config *conf;

    (void)err;

    if(!conn || !conn->state){
        return ERR_VAL;
    }

    state = (altcp_openssl_state_t *)conn->state;

    conf = (struct altcp_tls_config *)state->openssl_conf;

    state->openssl_ssl = create_openssl_ssl(conf->openssl_ctx, 0);

    if(!state->openssl_ssl){
        return ERR_ABRT;
    }

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

    if(p){
        altcp_recved(inner_conn, p->tot_len);
    }

    if(err != ERR_OK){
        err2 = ERR_ABRT;
        goto exit;
    }

    if(!conn || !conn->state){
        err2 = ERR_ABRT;
        goto exit;
    }

    state = (altcp_openssl_state_t *)conn->state;

    if(!p){
        if(state->handshake_done) {
            if(conn->recv) {
                err2 = conn->recv(conn->arg, conn, NULL, ERR_OK);
                goto exit;
            }
        } else {
            if(conn->err) {
                conn->err(conn->arg, ERR_ABRT);
            }
            altcp_close(conn);
        }
        err2 = ERR_OK;
        goto exit;
    }

    if(!state->openssl_ssl){
        goto exit;
    }

    pcurr = p;
    while(pcurr){
        put_data_into_ssl(state->openssl_ssl, (const char *)pcurr->payload, pcurr->len);
        pcurr = pcurr->next;
    }

    if(state->handshake_done){

        while(1){
            if(1/*SSL_has_pending(state->openssl_ssl)*/){
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
                        state = (altcp_openssl_state_t *)conn->state;
                        // conn and ssl may be already closed
                        if(!state || !state->openssl_ssl){
                            goto exit;
                        }
                    }else{
                        pbuf_free(buf);
                    }
                }else{
                    pbuf_free(buf);
                    break;
                }
            }else{
                break;
            }
        }

    }else{
        ret = do_handshake_process(state->openssl_ssl);
        get_data_from_ssl_and_send_out(state->openssl_ssl, inner_conn);
        if(ret >= 0){
            state->handshake_done = 1;
            if(state->ssl_is_server){
                if(conn->accept){
                    err2 = conn->accept(conn->arg, conn, ERR_OK);
                }
            }else{
                if(conn->connected){
                    err2 = conn->connected(conn->arg, conn, ERR_OK);
                }
            }

            while(1){
                if(1/*SSL_has_pending(state->openssl_ssl)*/){
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
                            state = (altcp_openssl_state_t *)conn->state;
                            // conn and ssl may be already closed
                            if(!state || !state->openssl_ssl){
                                goto exit;
                            }
                        }else{
                            pbuf_free(buf);
                        }
                    }else{
                        pbuf_free(buf);
                        break;
                    }
                }else{
                    break;
                }
            }
        }
    }

exit:

    if(p){
        pbuf_free(p);
    }

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

static err_t altcp_openssl_lower_accept(void *arg, struct altcp_pcb *accepted_conn, err_t err)
{
    struct altcp_pcb * listen_conn = (struct altcp_pcb *)arg;
    err_t setup_err;
    altcp_openssl_state_t *state;
    struct altcp_pcb *new_conn;

    (void)err;

    if(!(listen_conn && listen_conn->state && listen_conn->accept)){
        return ERR_ARG;
    }

    state = (altcp_openssl_state_t *)listen_conn->state;

    new_conn = altcp_alloc();
    if(!new_conn) {
        return ERR_MEM;
    }

    setup_err = altcp_openssl_setup(state->openssl_conf, new_conn, accepted_conn);
    if(setup_err != ERR_OK) {
        altcp_free(new_conn);
        return setup_err;
    }

    state = (altcp_openssl_state_t *)new_conn->state;

    state->openssl_ssl = create_openssl_ssl(((struct altcp_tls_config *)state->openssl_conf)->openssl_ctx, 1);
    if(!state->openssl_ssl){
        altcp_free(new_conn);
        return ERR_ABRT;
    }

    altcp_arg(new_conn, listen_conn->arg);
    altcp_accept(new_conn, listen_conn->accept);

    return ERR_OK;
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

static struct altcp_pcb *altcp_openssl_listen(struct altcp_pcb *conn, u8_t backlog, err_t *err)
{
    struct altcp_pcb *lpcb;

    if(!conn) {
        return NULL;
    }

    lpcb = altcp_listen_with_backlog_and_err(conn->inner_conn, backlog, err);
    if(lpcb != NULL) {
        altcp_openssl_state_t *state = (altcp_openssl_state_t *)conn->state;

        if(state->openssl_ssl){
            SSL_free(state->openssl_ssl);
            state->openssl_ssl = NULL;
        }

        conn->inner_conn = lpcb;
        altcp_accept(lpcb, altcp_openssl_lower_accept);
        return conn;
    }

    return NULL;
}

static const struct altcp_functions altcp_openssl_functions = {
  altcp_default_set_poll,
  altcp_openssl_recved,
  altcp_default_bind,
  altcp_openssl_connect,
  altcp_openssl_listen,
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
    state->openssl_conf = conf;
    state->ssl_is_server = config->openssl_is_server;

    altcp_openssl_setup_callbacks(conn, inner_conn);

    conn->inner_conn = inner_conn;
    conn->fns = &altcp_openssl_functions;

    return ERR_OK;

err:

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

