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

/* Simple SPDY client. */

#include <stdlib.h>

#include <apr_poll.h>
#include <apr_strings.h>
#include <apr_lib.h>

#include "simplespdy.h"


/* flags */
#define FLAG_STOP_WRITING 0x0001

typedef struct sspdy_context_t
{
    apr_pool_t *pool;

    sspdy_general_config_store_t *general_config_store;
    sspdy_config_store_t *config_store;

    const char *hostname;
    apr_socket_t *skt;

    /* Data to write on the connection */
    const char *data_out;
    apr_size_t data_len;
    apr_size_t data_cur;

    sspdy_stream_t *stream;

    int flags;

} sspdy_context_t;

apr_status_t sspdy_connect(sspdy_context_t *sspdy_ctx,
                           const char *hostname, apr_port_t port,
                           apr_pool_t *pool)
{
    apr_socket_t *skt;
    apr_sockaddr_t *host_address = NULL;
    apr_status_t status;

    STATUSERR(apr_sockaddr_info_get(&host_address, hostname,
                                    APR_UNSPEC, port, 0, pool));

    STATUSERR(apr_socket_create(&skt, host_address->family,
                                SOCK_STREAM, APR_PROTO_TCP, pool));

    STATUSERR(apr_socket_timeout_set(skt, 0));

    STATUSERR(apr_socket_opt_set(skt, APR_TCP_NODELAY, 1));
    
    status = apr_socket_connect(skt, host_address);
    if (status != APR_SUCCESS) {
        if (!APR_STATUS_IS_EINPROGRESS(status))
            return status;
    }

    sspdy_ctx->skt = skt;

    return APR_SUCCESS;
}

apr_status_t run_loop(sspdy_context_t *sspdy_ctx, apr_pool_t *pool)
{
    apr_pollset_t *pollset;
    apr_int32_t num;
    const apr_pollfd_t *desc;
    apr_status_t status;

    /* 10 seconds per loop */
    apr_short_interval_time_t duration = APR_USEC_PER_SEC * 10;

    STATUSERR(apr_pollset_create(&pollset, 32, pool, 0));

    if (sspdy_ctx->skt) {
        apr_pollfd_t pfd = { 0 };

        pfd.desc_type = APR_POLL_SOCKET;
        pfd.desc.s = sspdy_ctx->skt;
        pfd.reqevents = APR_POLLIN | APR_POLLHUP | APR_POLLERR;

        if (sspdy_ctx->data_cur < sspdy_ctx->data_len &&
            !sspdy_ctx->flags & FLAG_STOP_WRITING) {

            pfd.reqevents |= APR_POLLOUT;
        }

        status = apr_pollset_add(pollset, &pfd);
        if (status != APR_SUCCESS)
            goto cleanup;
    }

    status = apr_pollset_poll(pollset, duration, &num, &desc);
    if (status != APR_SUCCESS)
        goto cleanup;

    while (num--) {
        if (desc->desc.s == sspdy_ctx->skt) {
            if (desc->rtnevents & APR_POLLIN) {
                const char *data;
                apr_size_t len;

                sspdy_ctx->flags &= ~FLAG_STOP_WRITING;

                while (1) {
                    status = sspdy_stream_read(sspdy_ctx->stream, 100000, &data,
                                               &len);
                    sspdy__log_skt(LOG, __FILE__, sspdy_ctx->skt,
                                   "ssl_socket_read with status %d, len %d\n",
                                   status, len);
                    if (SSPDY_READ_ERROR(status))
                        goto cleanup;

                    if (len)
                        sspdy__log_skt(LOG, __FILE__, sspdy_ctx->skt,
                                       "read data of length %d:\n%.*s\n",
                                       len, len, data);

                    if (status == APR_EAGAIN)
                        break;
                };
            }
            if (desc->rtnevents & APR_POLLOUT) {

                if (sspdy_ctx->data_cur < sspdy_ctx->data_len) {
                    apr_size_t len = sspdy_ctx->data_len - sspdy_ctx->data_cur;
                    const char *ptr = sspdy_ctx->data_out + sspdy_ctx->data_cur;

                    status = sspdy_stream_write(sspdy_ctx->stream, ptr, &len);
                    if (status == SSPDY_SSL_WANTS_READ) {
                        /* Stop writing until next read */
                        sspdy_ctx->flags |= FLAG_STOP_WRITING;
                        status = APR_EAGAIN;
                    }
                    if (SSPDY_READ_ERROR(status))
                        goto cleanup;

                    if (len) {
                        sspdy_ctx->data_cur += len;
                        sspdy__log_skt(LOG, __FILE__, sspdy_ctx->skt,
                                       "wrote data of length %d:\n%.*s\n",
                                       len, len, ptr);
                    }
                }
            }
            if (desc->rtnevents & APR_POLLHUP ||
                desc->rtnevents & APR_POLLERR) {

                sspdy__log(LOG, __FILE__, "Reset event\n");
            }

        }
    }

cleanup:
    apr_pollset_destroy(pollset);

    return status;
}

apr_status_t init_sspdy_context(sspdy_context_t **sspdy_ctx, apr_pool_t *pool)
{
    apr_status_t status;

    sspdy_context_t *ctx = apr_pcalloc(pool, sizeof(sspdy_context_t));

    STATUSERR(apr_pool_create(&ctx->pool, pool));

    STATUSERR(create_config_store(&ctx->config_store, ctx->general_config_store,
                                  ctx->pool));

    *sspdy_ctx = ctx;

    return APR_SUCCESS;
}

#define CRLF "\r\n"

#define REQ "GET / HTTP/1.1" CRLF \
            "Host: lgo-ubuntu1:443" CRLF CRLF

int main(void)
{
    apr_pool_t *global_pool, *pool;
    apr_uri_t uri;
    const char *url = "https://lgo-ubuntu1";
    sspdy_context_t *sspdy_ctx;
    ssl_context_t *ssl_ctx;
    sspdy_stream_t *skt_stream;
    apr_size_t len;
    apr_status_t status;

    /* Initialize the Apache portable runtime library. */
    apr_initialize();
    atexit(apr_terminate);

    apr_pool_create(&global_pool, NULL);
    apr_pool_create(&pool, global_pool);

    (void)apr_uri_parse(pool, url, &uri);

    if (!uri.port) {
        uri.port = apr_uri_port_of_scheme(uri.scheme);
    }

    STATUSERR(init_sspdy_context(&sspdy_ctx, pool));

    STATUSERR(sspdy_connect(sspdy_ctx, uri.hostname, uri.port, pool));

    sspdy_ctx->data_out = REQ;
    sspdy_ctx->data_len = strlen(REQ);
    sspdy_ctx->data_cur = 0;
    sspdy_ctx->hostname = uri.hostname;

    ssl_ctx = init_ssl(pool, "spdy/3", sspdy_ctx->skt, uri.hostname);
    STATUSERR(sspdy_create_buf_stream(&sspdy_ctx->stream, ssl_socket_read,
                                      ssl_socket_write, ssl_ctx,
                                      pool));

    STATUSERR(sspdy_create_spdy_proto_stream(sspdy_ctx->config_store,
                                             &sspdy_ctx->stream,
                                             sspdy_ctx->stream,
                                             pool));
    while (1) {
        status = run_loop(sspdy_ctx, pool);
        if (!APR_STATUS_IS_TIMEUP(status) &&
             SSPDY_READ_ERROR(status)) {
            printf("\nFinish loop %d\n", status);
            goto cleanup;
        }
        printf(".");
    };
cleanup:
    printf("\n");

    /* Cleanup */
    apr_pool_destroy(global_pool);

    return 0;
}
