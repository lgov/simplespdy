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

#include <apr.h>
#include <apr_pools.h>
#include <apr_uri.h>


#define LOG 1

typedef struct sspdy_config_store_t sspdy_config_store_t;

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


#define SSPDY_READ_ERROR(status) ((status) \
                                 && !APR_STATUS_IS_EOF(status) \
                                 && !APR_STATUS_IS_EAGAIN(status) \
                                 && (status != SSPDY_SSL_WANTS_READ))

#define STATUSERR(x) if ((status = (x))) return status;

#define STATUSREADERR(x) if (((status = (x)) && SSPDY_READ_ERROR(status)))\
                           return status;

typedef struct ssl_context_t ssl_context_t;

ssl_context_t *init_ssl(apr_pool_t *pool, const char *proto,
                        apr_socket_t *skt, const char *hostname);


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

/* SPDY protocol stream */
apr_status_t sspdy_create_spdy_proto_stream(sspdy_config_store_t *,
                                            sspdy_stream_t **stream,
                                            sspdy_stream_t *wrapped,
                                            apr_pool_t *pool);

extern const sspdy_stream_type_t sspdy_stream_type_spdy_proto;


apr_status_t
ssl_socket_read(void *baton, char *data, apr_size_t *len);

apr_status_t
ssl_socket_write(void *baton, const char *data, apr_size_t *len);

typedef struct sspdy_general_config_store_t {

} sspdy_general_config_store_t;

struct sspdy_config_store_t {
    sspdy_general_config_store_t *general_config_store;
};

apr_status_t
create_general_config_store(sspdy_general_config_store_t **config_store,
                            apr_pool_t *pool);

apr_status_t
create_config_store(sspdy_config_store_t **config_store,
                    sspdy_general_config_store_t *general_config_store,
                    apr_pool_t *pool);

apr_status_t store_config_for_connection(apr_pool_t *pool);
