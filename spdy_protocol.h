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

#ifndef SPDY_PROTOCOL_H
#define SPDY_PROTOCOL_H

#include "protocols.h"
#include "config_store.h"

typedef struct compress_ctx_t compress_ctx_t;

typedef struct spdy_frame_hdr_t {
    apr_byte_t control;
    apr_byte_t flags;
    apr_uint32_t length;
    union {
        struct { /* control frame only */
            apr_uint16_t version;
            apr_uint16_t type;
        } ctrl;
        struct { /* data frame only */
            apr_uint32_t streamid;
        } data;
    };
} spdy_frame_hdr_t;


/* A large frame can probably not be read in one move, so we have to keep track
 of where we are. */
typedef enum {
    SPDY_FRAME_INIT,
    SPDY_FRAME_INPROGRESS,
    SPDY_FRAME_FINISHED,
} frame_read_state_t;

typedef struct sspdy_settings_frame_t {
    spdy_frame_hdr_t hdr;

    apr_uint32_t nr_of_entries;

    frame_read_state_t state;

} sspdy_settings_frame_t;

typedef struct sspdy_rst_stream_frame_t {
    spdy_frame_hdr_t hdr;

    apr_uint32_t status_code;

    frame_read_state_t state;

} sspdy_rst_stream_frame_t;

typedef struct sspdy_syn_reply_frame_t {
    spdy_frame_hdr_t hdr;

    apr_uint32_t streamid;

    frame_read_state_t state;

} sspdy_syn_reply_frame_t;

typedef struct sspdy_goaway_frame_t {
    spdy_frame_hdr_t hdr;

    apr_uint32_t last_good_streamid;

    apr_uint32_t status_code;

    frame_read_state_t state;
    
} sspdy_goaway_frame_t;

struct sspdy_data_frame_t {
    spdy_frame_hdr_t hdr;

    frame_read_state_t state;

};


#define READ_INT32(p, val)\
            val = ((const unsigned char)*p++ << 24) +\
                  ((const unsigned char)*p++ << 16) +\
                  ((const unsigned char)*p++ << 8)  +\
                   (const unsigned char)*p++;
#define READ_INT24(p, val)\
            val = ((const unsigned char)*p++ << 16) +\
                  ((const unsigned char)*p++ << 8)  +\
                   (const unsigned char)*p++;
#define READ_INT16(p, val)\
            val = ((const unsigned char)*p++ << 8)  +\
                   (const unsigned char)*p++;
#define READ_INT8(p, val)\
            val = (const unsigned char)*p++;

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

apr_status_t
init_compression(compress_ctx_t **z_ctx, apr_pool_t *pool);

struct spdy_proto_ctx_t
{
    apr_pool_t *pool;

    sspdy_config_store_t *config_store;
/*
    struct iovec vec[16];
    size_t vec_len;
    apr_size_t in_iov_pos;
*/

    /* priority request queue */
    spdy_request_t *req;

    /* incoming frames queue */
    spdy_frame_hdr_t *current_frame;
    serf_bucket_t *current_response;

    char hdr_data[8];
    apr_size_t available;
    apr_size_t in_cur_pos;

    compress_ctx_t *z_ctx;

    apr_uint32_t streamid;
};

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

apr_status_t sspdy_create_spdy_tls_protocol(sspdy_protocol_t **,
                                            sspdy_config_store_t *config_store,
                                            apr_pool_t *pool);

extern const sspdy_protocol_type_t sspdy_protocol_type_spdy;


#endif
