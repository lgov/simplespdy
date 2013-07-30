/* Copyright 2013 Lieven Govaerts
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "simplespdy.h"
#include "connections.h"

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static int init_done = 0;

struct ssl_context_t {
    apr_pool_t *pool;

    SSL_CTX* ctx;
    SSL* ssl;
    BIO *bio;

    apr_socket_t *skt;

    apr_status_t bio_read_status;

    /* queue of incoming data */

    /* Next Protocol Negotiation */
    const char *npn_data;
    int npn_len;
    apr_status_t npn_status;
};

#if LOG
/* Log all ssl alerts that we receive from the server. */
static void
apps_ssl_info_callback(const SSL *s, int where, int ret)
{
    const char *str;
    int w;
    w = where & ~SSL_ST_MASK;


    if (w & SSL_ST_CONNECT)
        str = "SSL_connect";
    else if (w & SSL_ST_ACCEPT)
        str = "SSL_accept";
    else
        str = "undefined";

    if (where & SSL_CB_LOOP) {
        sspdy__log(LOG, __FILE__, "%s:%s\n", str,
                   SSL_state_string_long(s));
    }
    else if (where & SSL_CB_ALERT) {
        str = (where & SSL_CB_READ) ? "read" : "write";
        sspdy__log(LOG, __FILE__, "SSL3 alert %s:%s:%s\n",
                   str,
                   SSL_alert_type_string_long(ret),
                   SSL_alert_desc_string_long(ret));
    }
    else if (where & SSL_CB_EXIT) {
        if (ret == 0)
            sspdy__log(LOG, __FILE__, "%s:failed in %s\n", str,
                       SSL_state_string_long(s));
        else if (ret < 0) {
            sspdy__log(LOG, __FILE__, "%s:error in %s\n", str,
                       SSL_state_string_long(s));
        }
    }
}
#endif

static int bio_apr_socket_create(BIO *bio)
{
    bio->shutdown = 1;
    bio->init = 1;
    bio->num = -1;
    bio->ptr = NULL;

    return 1;
}

static int bio_apr_socket_destroy(BIO *bio)
{
    /* Did we already free this? */
    if (bio == NULL) {
        return 0;
    }

    return 1;
}

static long bio_apr_socket_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    long ret = 1;

    switch (cmd) {
        default:
            /* abort(); */
            break;
        case BIO_CTRL_FLUSH:
            /* At this point we can't force a flush. */
            break;
        case BIO_CTRL_PUSH:
        case BIO_CTRL_POP:
            ret = 0;
            break;
    }
    return ret;
}

/* Returns the amount read. */
static int bio_apr_socket_read(BIO *bio, char *in, int inlen)
{
    apr_size_t len = inlen;
    ssl_context_t *ssl_ctx = bio->ptr;
    apr_status_t status;

    BIO_clear_retry_flags(bio);

    status = apr_socket_recv(ssl_ctx->skt, in, &len);
    ssl_ctx->bio_read_status = status;
    sspdy__log_skt(LOG, __FILE__, ssl_ctx->skt,
                   "bio_apr_socket_read read %d bytes with status %d\n", len,
                   status);

    if (APR_STATUS_IS_EAGAIN(status)) {
        BIO_set_retry_read(bio);
        if (len == 0)
            return -1;
    }

    if (status && !APR_STATUS_IS_EAGAIN(status) &&
        !APR_STATUS_IS_EOF(status)) {
        return -1;
    }

    return len;
}

static int bio_apr_socket_write(BIO *bio, const char *in, int inlen)
{
    apr_size_t len = inlen;
    ssl_context_t *ssl_ctx = bio->ptr;

    apr_status_t status = apr_socket_send(ssl_ctx->skt, in, &len);
    if (status && !APR_STATUS_IS_EAGAIN(status) &&
        !APR_STATUS_IS_EOF(status)) {
        return -1;
    }

    return len;
}


static BIO_METHOD bio_apr_socket_method = {
    BIO_TYPE_SOCKET,
    "APR sockets",
    bio_apr_socket_write,
    bio_apr_socket_read,
    NULL,                        /* Is this called? */
    NULL,                        /* Is this called? */
    bio_apr_socket_ctrl,
    bio_apr_socket_create,
    bio_apr_socket_destroy,
#ifdef OPENSSL_VERSION_NUMBER
    NULL /* sslc does not have the callback_ctrl field */
#endif
};

apr_status_t
ssl_socket_write(void *baton, const char *data, apr_size_t *len)
{
    ssl_context_t *ssl_ctx = baton;

    int result = SSL_write(ssl_ctx->ssl, data, *len);

    if (result > 0) {
        *len = result;
        return APR_SUCCESS;
    }
    else if (result == 0) {
        return APR_EAGAIN;
    } else {
        int ssl_err;

        ssl_err = SSL_get_error(ssl_ctx->ssl, result);
        switch (ssl_err) {
            case SSL_ERROR_SYSCALL:
                /* error in bio_bucket_read, probably APR_EAGAIN or APR_EOF */
                *len = 0;
                sspdy__log_skt(LOG, __FILE__, ssl_ctx->skt,
                               "ssl_socket_write maybe error %d, status: %d\n",
                               ssl_err, ssl_ctx->bio_read_status);
                return ssl_ctx->bio_read_status;
            case SSL_ERROR_WANT_READ:
                *len = 0;
                sspdy__log_skt(LOG, __FILE__, ssl_ctx->skt,
                               "ssl_socket_write want read\n");
                return SSPDY_SSL_WANTS_READ;
            case SSL_ERROR_SSL:
            default:
                *len = 0;
                sspdy__log_skt(LOG, __FILE__, ssl_ctx->skt,
                               "ssl_socket_write SSL Error %d: ", ssl_err);
                ERR_print_errors_fp(stderr);
                sspdy__log_nopref(LOG, "\n");
                return APR_EGENERAL;
        }
    }

    return APR_EGENERAL;
}

apr_status_t
ssl_socket_read(void *baton, char *data, apr_size_t *len)
{
    int result;
    ssl_context_t *ssl_ctx = baton;

    result = SSL_read(ssl_ctx->ssl, data, *len);
    if (result > 0) {
        sspdy__log_skt(LOG, __FILE__, ssl_ctx->skt,
                       "ssl_socket_read read %d bytes, bio status: %d\n",
                       result, ssl_ctx->bio_read_status);
        *len = result;
        return APR_SUCCESS;
    } else {
        int ssl_err;

        ssl_err = SSL_get_error(ssl_ctx->ssl, result);
        switch (ssl_err) {
            case SSL_ERROR_SYSCALL:
                /* error in bio_bucket_read, probably APR_EAGAIN or APR_EOF */
                *len = 0;
                sspdy__log_skt(LOG, __FILE__, ssl_ctx->skt,
                               "ssl_socket_read maybe error %d, status: %d\n",
                               ssl_err, ssl_ctx->bio_read_status);
                return ssl_ctx->bio_read_status;
            case SSL_ERROR_WANT_READ:
                *len = 0;
                sspdy__log_skt(LOG, __FILE__, ssl_ctx->skt,
                               "ssl_socket_read want read\n");
                return APR_EAGAIN;
            case SSL_ERROR_SSL:
            default:
                *len = 0;
                sspdy__log_skt(LOG, __FILE__, ssl_ctx->skt,
                               "ssl_socket_read SSL Error %d: ", ssl_err);
                ERR_print_errors_fp(stderr);
                sspdy__log_nopref(LOG, "\n");
                return APR_EGENERAL;
        }
    }
    
    /* not reachable */
    return APR_EGENERAL;
}


static int
ignore_server_cert(int cert_valid, X509_STORE_CTX *store_ctx)
{
    return 1;
}

static const char *
construct_nextproto(const char *proto, apr_size_t len, apr_pool_t *pool)
{
    char *out = apr_palloc(pool, len + 1);

    *out = len;
    memcpy(out + 1, proto, len);

    return out;
}

/*  */
static int
next_proto_cb(SSL *s, unsigned char **out, unsigned char *outlen,
              const unsigned char *in, unsigned int inlen, void *arg)
{
    ssl_context_t *ssl_ctx = arg;
    int i;

    sspdy__log_skt(LOG, __FILE__, ssl_ctx->skt,
                   "NPN Protocols advertized by server:\n");
    for (i = 0; i < inlen;) {
        unsigned char strlen = in[i];
        const unsigned char *str = &in[i+1];
        sspdy__log_skt(LOG, __FILE__, ssl_ctx->skt, "%.*s\n", strlen, str);
        i += strlen + 1;
    }

    ssl_ctx->npn_status = SSL_select_next_proto(out, outlen, in, inlen,
                                                (const unsigned char*)ssl_ctx->npn_data,
                                                ssl_ctx->npn_len);
    if (ssl_ctx->npn_status == OPENSSL_NPN_NEGOTIATED) {
        sspdy__log_skt(LOG, __FILE__, ssl_ctx->skt,
                       "NPN Protocol %s negotiated, status %d\n",
                       ssl_ctx->npn_data,
                       ssl_ctx->npn_status);
    } else if (ssl_ctx->npn_status == OPENSSL_NPN_NO_OVERLAP) {
        sspdy__log_skt(LOG, __FILE__, ssl_ctx->skt,
                       "NPN Protocol %s not available, status %d\n",
                       ssl_ctx->npn_data,
                       ssl_ctx->npn_status);
    }

    return SSL_TLSEXT_ERR_OK;
}

ssl_context_t *init_ssl(apr_pool_t *pool, const char *proto,
                        apr_socket_t *skt, const char *hostname)
{
    ssl_context_t *ssl_ctx = apr_pcalloc(pool, sizeof(*ssl_ctx));
    ssl_ctx->pool = pool;
    ssl_ctx->skt = skt;

    /* Init OpenSSL globally */
    if (!init_done)
    {
        CRYPTO_malloc_init();
        ERR_load_crypto_strings();
        SSL_load_error_strings();
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        init_done = 1;
    }

    /* Setup context */
    /* NPN requires TLSv1_client_method() */
    ssl_ctx->ctx = SSL_CTX_new(TLSv1_client_method());
    SSL_CTX_set_verify(ssl_ctx->ctx, SSL_VERIFY_PEER, ignore_server_cert);
    SSL_CTX_set_options(ssl_ctx->ctx, SSL_OP_ALL);

#if LOG
    SSL_CTX_set_info_callback(ssl_ctx->ctx, apps_ssl_info_callback);
#endif

    /* Setup spdy negotiation */
#if OPENSSL_VERSION_NUMBER >= 0x10001000L && !defined(OPENSSL_NO_TLSEXT) && \
!defined(OPENSSL_NO_NEXTPROTONEG)
    SSL_CTX_set_next_proto_select_cb(ssl_ctx->ctx, next_proto_cb, ssl_ctx);
    ssl_ctx->npn_len = strlen(proto);
    ssl_ctx->npn_data = construct_nextproto(proto, ssl_ctx->npn_len, pool);
#endif

    ssl_ctx->bio = BIO_new(&bio_apr_socket_method);
    ssl_ctx->bio->ptr = ssl_ctx;

    /* Setup SSL structure */
    ssl_ctx->ssl = SSL_new(ssl_ctx->ctx);
    SSL_set_cipher_list(ssl_ctx->ssl, "ALL");
    SSL_set_bio(ssl_ctx->ssl, ssl_ctx->bio, ssl_ctx->bio);
    SSL_set_connect_state(ssl_ctx->ssl);
    SSL_set_app_data(ssl_ctx->ssl, ssl_ctx);
    SSL_set_tlsext_host_name(ssl_ctx->ssl, hostname);
    
    return ssl_ctx;
}
