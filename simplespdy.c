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
#include "config_store.h"
#include "protocols.h"
#include "connections.h"

typedef struct sspdy_context_t
{
    apr_pool_t *pool;

    sspdy_general_config_store_t *general_config_store;
    sspdy_config_store_t *config_store;

    const char *hostname;

    sspdy_stream_t *stream;
    sspdy_protocol_t *proto;
    sspdy_connection_t *conn;
} sspdy_context_t;

apr_status_t run_loop(sspdy_context_t *sspdy_ctx, apr_pool_t *pool)
{
    apr_pollset_t *pollset;
    apr_int32_t num;
    const apr_pollfd_t *desc;
    apr_status_t status;

    /* 10 seconds per loop */
    apr_short_interval_time_t duration = APR_USEC_PER_SEC * 10;

    STATUSERR(apr_pollset_create(&pollset, 32, pool, 0));

    status = sspdy_connection_update_pollset(sspdy_ctx->conn, pollset);
    if (status != APR_SUCCESS)
        goto cleanup;

    status = apr_pollset_poll(pollset, duration, &num, &desc);
    if (status != APR_SUCCESS)
        goto cleanup;

    while (num--) {
        sspdy_connection_t *conn = desc->client_data;
        if (conn) {
            if (desc->rtnevents & APR_POLLIN) {
                const char *data;
                apr_size_t len;

                while (1) {
                    status = sspdy_connection_read(sspdy_ctx->conn, 100000,
                                                   &data, &len);
                    if (SSPDY_READ_ERROR(status))
                        goto cleanup;

                    if (len) {
                        STATUSERR(sspdy_proto_data_available(sspdy_ctx->proto,
                                                             data, len));
                    }

                    if (status == APR_EAGAIN)
                        break;
                };
            }
            if (desc->rtnevents & APR_POLLOUT) {

                apr_size_t len;
                const char *data;

                STATUSREADERR(sspdy_proto_read(sspdy_ctx->proto, 100000,
                                               &data, &len));

                status = sspdy_connection_write(sspdy_ctx->conn, data, &len);
                if (SSPDY_READ_ERROR(status))
                    goto cleanup;
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
#if 0
int main(void)
{
    apr_pool_t *global_pool, *pool;
    sspdy_context_t *sspdy_ctx;
    apr_status_t status;

    /* Initialize the Apache portable runtime library. */
    apr_initialize();
    atexit(apr_terminate);

    apr_pool_create(&global_pool, NULL);
    apr_pool_create(&pool, global_pool);

    STATUSERR(init_sspdy_context(&sspdy_ctx, pool));

    STATUSERR(sspdy_create_spdy_proto_stream(sspdy_ctx->config_store,
                                             &sspdy_ctx->stream,
                                             sspdy_ctx->stream,
                                             pool));
    test(sspdy_ctx->stream, pool);

    return 0;
}
#endif

apr_status_t response_handler()
{
    return APR_SUCCESS;
}

apr_status_t setup_request(void *baton, const char **data,
                           apr_size_t *len)
{
    return APR_SUCCESS;
}

#include "spdy_protocol.h"

int main(void)
{
    apr_pool_t *global_pool, *pool;
    apr_uri_t uri;
    const char *url = "https://www.google.be";
    sspdy_context_t *sspdy_ctx;
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

    sspdy_ctx->hostname = uri.hostname;

    STATUSERR(sspdy_create_tls_connection(&sspdy_ctx->conn,
                                          sspdy_ctx->config_store,
                                          uri.hostname, uri.port,
                                          pool));

    STATUSERR(sspdy_create_spdy_tls_protocol(&sspdy_ctx->proto,
                                             sspdy_ctx->config_store,
                                             pool));

    STATUSERR(sspdy_proto_queue_request(sspdy_ctx->proto, setup_request,
                                        sspdy_ctx));

    while (1) {
        status = run_loop(sspdy_ctx, pool);
        if (!APR_STATUS_IS_TIMEUP(status) &&
             SSPDY_READ_ERROR(status)) {
            printf("\nFinish loop %d\n", status);
            goto cleanup;
        }
/*        if (status == APR_EOF)
            goto cleanup;
*/
        printf(".");
    };
cleanup:
    printf("\n");

    /* Cleanup */
    apr_pool_destroy(global_pool);

    return 0;
}
