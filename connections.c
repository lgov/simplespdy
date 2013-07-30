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

/* flags */
#define FLAG_STOP_WRITING 0x0001


apr_status_t sspdy_connection_read(sspdy_connection_t *conn,
                                   apr_size_t requested,
                                   const char **data, apr_size_t *len)
{
    return conn->type->read(conn, requested, data, len);
}

apr_status_t sspdy_connection_write(sspdy_connection_t *conn, const char *data,
                                    apr_size_t *len)
{
    return conn->type->write(conn, data, len);
}

apr_status_t sspdy_connection_update_pollset(sspdy_connection_t *conn,
                                             apr_pollset_t *pollset)
{
    return conn->type->update_pollset(conn, pollset);
}

typedef struct tls_conn_ctx_t {
    apr_pool_t *pool;

    sspdy_config_store_t *config_store;

    ssl_context_t *ssl_ctx;
    apr_socket_t *skt;

    sspdy_stream_t *stream;

    int flags;
} tls_conn_ctx_t;

apr_status_t sspdy_connect(apr_socket_t **skt,
                           const char *hostname, apr_port_t port,
                           apr_pool_t *pool)
{
    apr_sockaddr_t *host_address = NULL;
    apr_status_t status;

    STATUSERR(apr_sockaddr_info_get(&host_address, hostname,
                                    APR_UNSPEC, port, 0, pool));

    STATUSERR(apr_socket_create(skt, host_address->family,
                                SOCK_STREAM, APR_PROTO_TCP, pool));

    STATUSERR(apr_socket_timeout_set(*skt, 0));

    STATUSERR(apr_socket_opt_set(*skt, APR_TCP_NODELAY, 1));

    status = apr_socket_connect(*skt, host_address);
    if (status != APR_SUCCESS) {
        if (!APR_STATUS_IS_EINPROGRESS(status))
            return status;
    }

    return APR_SUCCESS;
}

apr_status_t
sspdy_create_tls_connection(sspdy_connection_t ** conn,
                            sspdy_config_store_t *config_store,
                            const char *hostname, apr_port_t port,
                            apr_pool_t *pool)
{
    tls_conn_ctx_t *ctx;
    apr_status_t status;

    ctx = apr_pcalloc(pool, sizeof(tls_conn_ctx_t));
    ctx->pool = pool;
    ctx->config_store = config_store;

    STATUSERR(sspdy_connect(&ctx->skt, hostname, port, pool));

    ctx->ssl_ctx = init_ssl(pool, "spdy/3", ctx->skt, hostname);
    STATUSERR(sspdy_create_buf_stream(&ctx->stream, ssl_socket_read,
                                      ssl_socket_write, ctx->ssl_ctx,
                                      pool));

    *conn = apr_palloc(pool, sizeof(sspdy_connection_t));
    (*conn)->type = &sspdy_connection_type_tls;
    (*conn)->data = ctx;

    return APR_SUCCESS;
}

apr_status_t sspdy_spdy_tls_connection_read(sspdy_connection_t *conn,
                                            apr_size_t requested,
                                            const char **data, apr_size_t *len)
{
    tls_conn_ctx_t *ctx = conn->data;
    apr_status_t status;

    ctx->flags &= ~FLAG_STOP_WRITING;

    status = sspdy_stream_read(ctx->stream, requested, data, len);
    sspdy__log_skt(LOG, __FILE__, ctx->skt,
                   "sspdy_spdy_tls_connection_read with status %d, len %d\n",
                   status, *len);

    return status;
}

apr_status_t sspdy_spdy_tls_connection_write(sspdy_connection_t *conn,
                                             const char *data, apr_size_t *len)
{
    tls_conn_ctx_t *ctx = conn->data;
    apr_status_t status = APR_SUCCESS;

    status = sspdy_stream_write(ctx->stream, data, len);
    if (status == SSPDY_SSL_WANTS_READ) {
        /* Stop writing until next read */
        ctx->flags |= FLAG_STOP_WRITING;
        status = APR_EAGAIN;
    }
    if (status == APR_EOF)
        ctx->flags |= FLAG_STOP_WRITING;

    sspdy__log_skt(LOG, __FILE__, ctx->skt,
                   "sspdy_spdy_tls_connection_write with status %d, len %d\n",
                   status, *len);

    return APR_SUCCESS;
}

apr_status_t sspdy_spdy_tls_update_pollset(sspdy_connection_t *conn,
                                           apr_pollset_t *pollset)
{
    tls_conn_ctx_t *ctx = conn->data;
    apr_pollfd_t pfd = { 0 };

    pfd.desc_type = APR_POLL_SOCKET;
    pfd.desc.s = ctx->skt;
    pfd.client_data = conn;
    pfd.reqevents = APR_POLLIN | APR_POLLHUP | APR_POLLERR;

    if (!ctx->flags & FLAG_STOP_WRITING) {

        pfd.reqevents |= APR_POLLOUT;
    }

    return apr_pollset_add(pollset, &pfd);
}

const sspdy_connection_type_t sspdy_connection_type_tls = {
    "TLSCONNECTION",
    sspdy_spdy_tls_connection_read,
    sspdy_spdy_tls_connection_write,
    sspdy_spdy_tls_update_pollset,
};
