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

#include <stdlib.h>
#include <apr.h>
#include <apr_network_io.h>

#include "simplespdy.h"

static void log_time()
{
    apr_time_exp_t tm;

    apr_time_exp_lt(&tm, apr_time_now());
    fprintf(stderr, "%d-%02d-%02dT%02d:%02d:%02d.%06d%+03d ",
            1900 + tm.tm_year, 1 + tm.tm_mon, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_usec,
            tm.tm_gmtoff/3600);
}

void sspdy__log(int verbose_flag, const char *filename, const char *fmt, ...)
{
    va_list argp;

    if (verbose_flag) {
        log_time();

        if (filename)
            fprintf(stderr, "%s: ", filename);

        va_start(argp, fmt);
        vfprintf(stderr, fmt, argp);
        va_end(argp);
    }
}

void sspdy__log_nopref(int verbose_flag, const char *fmt, ...)
{
    va_list argp;

    if (verbose_flag) {
        va_start(argp, fmt);
        vfprintf(stderr, fmt, argp);
        va_end(argp);
    }
}

void sspdy__log_skt(int verbose_flag, const char *filename, apr_socket_t *skt,
                    const char *fmt, ...)
{
    va_list argp;

    if (verbose_flag) {
        apr_sockaddr_t *sa;
        log_time();

        if (skt) {
            /* Log local and remote ip address:port */
            fprintf(stderr, "[l:");
            if (apr_socket_addr_get(&sa, APR_LOCAL, skt) == APR_SUCCESS) {
                char buf[32];
                apr_sockaddr_ip_getbuf(buf, 32, sa);
                fprintf(stderr, "%s:%d", buf, sa->port);
            }
            fprintf(stderr, " r:");
            if (apr_socket_addr_get(&sa, APR_REMOTE, skt) == APR_SUCCESS) {
                char buf[32];
                apr_sockaddr_ip_getbuf(buf, 32, sa);
                fprintf(stderr, "%s:%d", buf, sa->port);
            }
            fprintf(stderr, "] ");
        }

        if (filename)
            fprintf(stderr, "%s: ", filename);

        va_start(argp, fmt);
        vfprintf(stderr, fmt, argp);
        va_end(argp);
    }
}


apr_status_t sspdy_stream_read(sspdy_stream_t *stream, apr_size_t requested,
                               const char **data, apr_size_t *len)
{
    return stream->type->read(stream, requested, data, len);
}

apr_status_t sspdy_stream_write(sspdy_stream_t *stream, const char *data,
                                apr_size_t *len)
{
    return stream->type->write(stream, data, len);
}

typedef struct sspdy_buf_stream_ctx_t
{
    readfunc_t read;
    writefunc_t write;
    apr_pool_t *pool;
    void *baton;

    char *in_data;
    apr_size_t remaining;

    char *out_data;
    apr_size_t available;
} sspdy_buf_stream_ctx_t;

apr_status_t
sspdy_create_buf_stream(sspdy_stream_t **stream,
                        readfunc_t read, writefunc_t write,
                        void *baton,
                        apr_pool_t *pool)
{
    sspdy_buf_stream_ctx_t *ctx;

    ctx = apr_pcalloc(pool, sizeof(sspdy_buf_stream_ctx_t));
    ctx->read = read;
    ctx->write = write;
    ctx->baton = baton;
    ctx->pool = pool;

    *stream = apr_palloc(pool, sizeof(sspdy_stream_t));
    (*stream)->type = &sspdy_stream_type_buffered;
    (*stream)->data = ctx;

    return APR_SUCCESS;
}

apr_status_t sspdy_buf_read(sspdy_stream_t *stream, apr_size_t requested,
                            const char **data, apr_size_t *len)
{
    char buf[16384];
    apr_size_t bufsize = 16384;
    sspdy_buf_stream_ctx_t *ctx = stream->data;
    apr_status_t status;

    if (!ctx->remaining) {
        status = ctx->read(ctx->baton, buf, &bufsize);

        if (bufsize) {
            ctx->in_data = apr_palloc(ctx->pool, bufsize);
            memcpy(ctx->in_data, buf, bufsize);
            ctx->remaining = bufsize;
        }
    }

    if (ctx->remaining) {
        *data = ctx->in_data;
        if (requested <= ctx->remaining) {
            ctx->in_data += requested;
            *len = requested;
            ctx->remaining -= requested;
            return APR_SUCCESS;
        } else {
            ctx->in_data += ctx->remaining;
            *len = ctx->remaining;
            ctx->remaining = 0;
            return APR_EAGAIN;
        }
    } else {
        *len = 0;
    }

    return status;
}

apr_status_t sspdy_buf_write(sspdy_stream_t *stream,
                             const char *data, apr_size_t *len)
{
    sspdy_buf_stream_ctx_t *ctx = stream->data;
    apr_status_t status;

    status = ctx->write(ctx->baton, data, len);

    /* TODO: buffer data */

    return status;
}

const sspdy_stream_type_t sspdy_stream_type_buffered = {
    "SOCKET",
    sspdy_buf_read,
    sspdy_buf_write,
};
