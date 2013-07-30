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

#ifndef SIMPLE_SPDY_H
#define SIMPLE_SPDY_H

#include <apr.h>
#include <apr_pools.h>
#include <apr_uri.h>
#include <apr_hash.h>

#define LOG 1

typedef struct compress_ctx_t compress_ctx_t;
typedef struct spdy_proto_ctx_t spdy_proto_ctx_t;

static void log_time();
void sspdy__log(int verbose_flag, const char *filename, const char *fmt, ...);
void sspdy__log_skt(int verbose_flag, const char *filename, apr_socket_t *skt,
                    const char *fmt, ...);
void sspdy__log_nopref(int verbose_flag, const char *fmt, ...);


#define SSPDY_ERROR_RANGE 400
#define SSPDY_ERROR_START (APR_OS_START_USERERR + SSPDY_ERROR_RANGE)

/* Stop writing until more data is read. */
#define SSPDY_SSL_WANTS_READ (SSPDY_ERROR_START + 1)

/* Stop creating new streams on this connection. */
#define SSPDY_SPDY_MAXIMUM_STREAMID (SSPDY_ERROR_START + 2)

#define SSPDY_SPDY_PROTOCOL_ERROR (SSPDY_ERROR_START + 3)

#define SSPDY_READ_ERROR(status) ((status) \
                                 && !APR_STATUS_IS_EOF(status) \
                                 && !APR_STATUS_IS_EAGAIN(status) \
                                 && (status != SSPDY_SSL_WANTS_READ))

#define STATUSERR(x) if ((status = (x))) return status;

#define STATUSREADERR(x) if (((status = (x)) && SSPDY_READ_ERROR(status)))\
                           return status;

typedef struct sspdy_stream_type_t sspdy_stream_type_t;

typedef struct sspdy_stream_t {
    /** the type of this stream */
    const sspdy_stream_type_t *type;

    /** private data */
    void *data;
} sspdy_stream_t;

struct sspdy_stream_type_t {
    const char *name;

    apr_status_t (*read)(sspdy_stream_t *stream, apr_size_t requested,
                         const char **data, apr_size_t *len);

    apr_status_t (*write)(sspdy_stream_t *stream, const char *data,
                          apr_size_t *len);

    void (*destroy)(sspdy_stream_t *stream);
};

apr_status_t sspdy_stream_read(sspdy_stream_t *stream, apr_size_t requested,
                               const char **data, apr_size_t *len);
apr_status_t sspdy_stream_write(sspdy_stream_t *stream, const char *data,
                                apr_size_t *len);

/* Buffered stream */
extern const sspdy_stream_type_t sspdy_stream_type_buffered;

typedef apr_status_t (*readfunc_t)(void *baton, char *data, apr_size_t *len);

typedef apr_status_t (*writefunc_t)(void *baton, const char *data,
apr_size_t *len);

apr_status_t
sspdy_create_buf_stream(sspdy_stream_t **stream,
                        readfunc_t read, writefunc_t write, void *baton,
                        apr_pool_t *pool);

/* SPDY OUT/SYN_STREAM */
extern const sspdy_stream_type_t sspdy_stream_type_spdy_out_syn_stream;

apr_status_t sspdy_create_spdy_out_syn_stream(sspdy_stream_t **stream,
                                              spdy_proto_ctx_t *spdy_ctx,
                                              apr_hash_t *hdrs,
                                              apr_pool_t *pool);

/* SPDY IN/DATA */
extern const sspdy_stream_type_t sspdy_stream_type_spdy_in_data;

/* SPDY protocol */

apr_status_t
ssl_socket_read(void *baton, char *data, apr_size_t *len);

apr_status_t
ssl_socket_write(void *baton, const char *data, apr_size_t *len);

/* ZLib compression */

apr_status_t
init_compression(compress_ctx_t **z_ctx, apr_pool_t *pool);

apr_status_t compressbuf(const char **data, apr_size_t *len,
                         compress_ctx_t *z_ctx,
                         const char* orig, apr_size_t orig_len,
                         apr_pool_t *pool);

apr_status_t decompressbuf(const char **data, apr_size_t *len,
                           compress_ctx_t *z_ctx,
                           const char* orig, apr_size_t orig_len,
                           apr_pool_t *pool);

apr_status_t test(sspdy_stream_t *stream, apr_pool_t *pool);

apr_status_t
init_compression(compress_ctx_t **z_ctx, apr_pool_t *pool);


#endif
