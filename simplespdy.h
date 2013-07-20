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
#include <apr_hash.h>

#define LOG 1

typedef struct sspdy_config_store_t sspdy_config_store_t;
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

/* SPDY OUT/SYN_STREAM */
extern const sspdy_stream_type_t sspdy_stream_type_spdy_out_syn_stream;

apr_status_t sspdy_create_spdy_out_syn_stream(sspdy_stream_t **stream,
                                              spdy_proto_ctx_t *spdy_ctx,
                                              apr_hash_t *hdrs,
                                              apr_pool_t *pool);



/*************************/
/* Protocol declarations */
/*************************/
typedef struct sspdy_protocol_type_t sspdy_protocol_type_t;

typedef struct sspdy_protocol_t {
    /** the type of this protocol */
    const sspdy_protocol_type_t *type;

    /** private data */
    void *data;
} sspdy_protocol_t;


typedef apr_status_t (*sspdy_setup_request_t)(void *baton, const char **data,
                                              apr_size_t *len);

struct sspdy_protocol_type_t {
    const char *name;
/*
    apr_status_t (*read)(sspdy_stream_t *stream, apr_size_t requested,
                         const char **data, apr_size_t *len);
*/
    apr_status_t (*data_available)(sspdy_protocol_t *proto, const char *data,
                                   apr_size_t len);

    apr_status_t (*new_request)(sspdy_protocol_t *proto,
                                sspdy_setup_request_t setup_request,
                                void *setup_baton);

    apr_status_t (*read)(sspdy_protocol_t *proto, apr_size_t requested,
                         const char **data, apr_size_t *len);

    void (*destroy)(sspdy_protocol_t *proto);
};

/* SPDY protocol */

typedef enum {
    SPDY_CTRL_SYN_STREAM = 1,
    SPDY_CTRL_REPLY      = 2,
    SPDY_CTRL_RST_STREAM = 3,
    SPDY_CTRL_SETTINGS   = 4,
    SPDY_CTRL_GOAWAY     = 7,
} sspdy_ctrl_frame_type_t;

typedef enum {
    SPDY_STATUS_PROTOCOL_ERROR = 1,
    SPDY_STATUS_INTERNAL_ERROR = 7,
} sspdy_status_code_t;

typedef enum {
    /* SYN_STREAM */
    SSPDY_FLAG_HDR_FLAG_FIN       = 0x1,
    /* SYN_STREAM and SYN_REPLY */
    SSPDY_FLAG_HDR_UNIDIRECTIONAL = 0x2,
    /* SETTINGS frame */
    SSPDY_FLAG_HDR_CLEAR_SETTINGS = 0x1,

} sspdy_header_flags_t;

typedef struct hdr_val_pair_t {
    const char *hdr;
    const char *val;
} hdr_val_pair_t;

typedef struct spdy_request_t {
    sspdy_setup_request_t setup_request;
    void *setup_baton;
} spdy_request_t;

struct spdy_proto_ctx_t
{
    apr_pool_t *pool;

    sspdy_config_store_t *config_store;

    struct iovec vec[16];
    size_t vec_len;

    spdy_request_t *req;

    /*    const char *in_data;*/
    apr_size_t available;
    apr_size_t in_cur_pos;
    apr_size_t in_iov_pos;

    compress_ctx_t *z_ctx;

    const char *frame_buf;

    apr_uint32_t streamid;
};

apr_status_t sspdy_create_spdy_protocol(sspdy_protocol_t **,
                                        sspdy_config_store_t *config_store,
                                        apr_pool_t *pool);

extern const sspdy_protocol_type_t sspdy_protocol_type_spdy;

apr_status_t sspdy_proto_new_request(sspdy_protocol_t *proto,
                                     sspdy_setup_request_t setup_request,
                                     void *setup_baton);
apr_status_t sspdy_proto_data_available(sspdy_protocol_t *proto,
                                        const char *data, apr_size_t len);
apr_status_t sspdy_proto_read(sspdy_protocol_t *proto, apr_size_t requested,
                              const char **data, apr_size_t *len);

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
