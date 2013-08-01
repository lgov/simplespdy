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
#include "spdy_protocol.h"
#include "spdy_buckets.h"

/* Utility functions */
#define MAX_STREAMID 0x7FFFFFFF

static apr_status_t
next_streamid(apr_uint32_t *streamid, spdy_proto_ctx_t *ctx)
{
    if (ctx->streamid > MAX_STREAMID)
        return SSPDY_SPDY_MAXIMUM_STREAMID;

    *streamid = ctx->streamid;
    ctx->streamid += 2; /* next id, always odd numbers for client-initiated
                         streams */
    return APR_SUCCESS;
}


#define WRITE_INT32(p, val)\
            *p++ = ((val) >> 24) & 0xff;\
            *p++ = ((val) >> 16) & 0xff;\
            *p++ = ((val) >> 8) & 0xff;\
            *p++ = ((val)) & 0xff;

#define WRITE_INT24(p, val)\
            *p++ = ((val) >> 16) & 0xff;\
            *p++ = ((val) >> 8) & 0xff;\
            *p++ = ((val)) & 0xff;


/* SYN_STREAM stream */
#define BUFSIZE 16384

typedef struct spdy_syn_bucket_ctx_t {
    spdy_proto_ctx_t *spdy_ctx;
    apr_hash_t *hdrs;
    apr_pool_t *pool;
    char *out_data;
    apr_size_t out_cur_pos;
    compress_ctx_t *z_ctx;
} spdy_syn_bucket_ctx_t;

apr_status_t
sspdy_create_spdy_out_syn_bucket(serf_bucket_t **bkt,
                                 spdy_proto_ctx_t *spdy_ctx,
                                 apr_hash_t *hdrs,
                                 apr_pool_t *pool)
{
    spdy_syn_bucket_ctx_t *ctx;
    apr_status_t status;

    ctx = apr_pcalloc(pool, sizeof(spdy_syn_bucket_ctx_t));
    ctx->spdy_ctx = spdy_ctx;
    ctx->hdrs = hdrs;
    ctx->out_data = apr_palloc(pool, BUFSIZE);
    ctx->pool = pool;
    STATUSERR(init_compression(&ctx->z_ctx, ctx->pool));

    *bkt = apr_palloc(pool, sizeof(serf_bucket_t));
    (*bkt)->type = &serf_bucket_type_out_syn;
    (*bkt)->data = ctx;

    return APR_SUCCESS;
}

static apr_status_t
create_compressed_header_block(spdy_syn_bucket_ctx_t *ctx, const char **data,
                               apr_uint32_t *len, apr_pool_t *pool)
{
    apr_uint32_t nr_of_hdrs;
    const char *hdr = "Host";
    const char *value = "lgo:ubuntu1:443";
    char *buf = apr_palloc(pool, 4096);
    char *p = buf;
    apr_size_t uncomp_len, comp_len;
    apr_status_t status;
    int i;

    hdr_val_pair_t headers[] = {
        { ":method", "GET" },
        { ":path", "/" },
        { ":version", "HTTP/1.1" },
        { ":host", "www.google.be" },
        { ":scheme", "https" },
    };

    nr_of_hdrs = sizeof(headers) / sizeof(headers[0]);
    WRITE_INT32(p, nr_of_hdrs);

    for (i = 0; i < nr_of_hdrs; i++) {
        apr_uint32_t length;

        length = strlen(headers[i].hdr);
        WRITE_INT32(p, length);
        memcpy(p, headers[i].hdr, length);
        p += length;

        length = strlen(headers[i].val);
        WRITE_INT32(p, length);
        memcpy(p, headers[i].val, length);
        p += length;
    }

    uncomp_len = p - buf;

    STATUSERR(compressbuf(data, &comp_len, ctx->z_ctx, buf, uncomp_len, pool));

    if (comp_len > 0x7fffffff)
        return SSPDY_SPDY_PROTOCOL_ERROR;

    *len = (apr_uint32_t)comp_len;
    
    return APR_SUCCESS;
}

static apr_status_t
write_spdy_syn_stream_frame(spdy_syn_bucket_ctx_t *ctx,
                            apr_size_t *len,
                            apr_pool_t *pool)
{
    char *p = ctx->out_data;
    const char *hdrs;
    apr_size_t total_length;
    apr_uint32_t streamid, length, hdrs_len;
    apr_pool_t *tmp_pool;
    apr_status_t status;

    STATUSERR(next_streamid(&streamid, ctx->spdy_ctx));

    STATUSERR(apr_pool_create(&tmp_pool, pool));
    STATUSERR(create_compressed_header_block(ctx, &hdrs, &hdrs_len, tmp_pool));

    length = 10 + hdrs_len;
    *len = length + 8;

    /* SYN_STREAM */
    *p++ = 0x80; /* Control bit and Version*/
    *p++ = 0x03;
    *p++ = 0x00; /* SYN_STREAM */
    *p++ = 0x01;

    /* HEAD request, no data */
    *p++ = SSPDY_FLAG_HDR_FLAG_FIN; /* Flags */

    WRITE_INT24(p, length);

    streamid &= 0x7fffffff;
    WRITE_INT32(p, streamid); /* first bit isn't used */

    WRITE_INT32(p, 0 & 0x7fffffff); /* Associated Stream ID */

    *p++ = 0x00; /* Priority and Unused */
    *p++ = 0x00; /* Slot */

    memcpy(p, hdrs, hdrs_len);

    sspdy__log(LOG, __FILE__, "Prepare SYN_STREAM frame.\n");

    apr_pool_destroy(tmp_pool);
    
    return status;
}

static apr_status_t
sspdy_spdy_out_syn_bucket_read(serf_bucket_t *bkt,
                               apr_size_t requested,
                               const char **data, apr_size_t *len)
{
    spdy_syn_bucket_ctx_t *ctx = bkt->data;
    apr_status_t status;
    
    STATUSERR(write_spdy_syn_stream_frame(ctx, len, ctx->pool));
    if (*len > requested) {
        ctx->out_cur_pos = *len;
        *len = requested;
    }

    *data = ctx->out_data;

    return APR_SUCCESS;
}

const serf_bucket_type_t serf_bucket_type_out_syn = {
    "OUT/SPDY_SYN_BUCKET",
    sspdy_spdy_out_syn_bucket_read,
    NULL,
};
/* ===========================================================================*/

typedef struct spdy_data_ctx_t {
    sspdy_data_frame_t *frame;
    apr_pool_t *pool;
    serf_bucket_t *wrapped;
    apr_uint32_t remaining;
} spdy_data_ctx_t;

apr_status_t
sspdy_create_response_bucket(serf_bucket_t **bkt,
                             apr_pool_t *pool)
{
    spdy_data_ctx_t *ctx;
    apr_status_t status;

    ctx = apr_pcalloc(pool, sizeof(spdy_data_ctx_t));
    ctx->pool = pool;

    *bkt = apr_palloc(pool, sizeof(serf_bucket_t));
    (*bkt)->type = &serf_bucket_type_spdy_in_data;
    (*bkt)->data = ctx;

    return APR_SUCCESS;
}

apr_status_t sspdy_spdy_in_data_read(serf_bucket_t *bkt,
                                     apr_size_t requested,
                                     const char **data, apr_size_t *len)
{
    spdy_data_ctx_t *ctx = bkt->data;
    apr_status_t status;

    if (!ctx->wrapped)
        return APR_EOF;

    STATUSREADERR(serf_bucket_read(ctx->wrapped, requested, data, len));

    if (*len)
        ctx->remaining -= *len;

    sspdy__log(LOG, __FILE__, "data frame: %d bytes remaining\n", ctx->remaining);

    if (status == APR_EOF) {
        if (ctx->remaining)
            return APR_EAGAIN;
        else {
            if (ctx->frame->hdr.flags & SSPDY_FLAG_HDR_FLAG_FIN) {
                return APR_EOF;
            } else {
                return SSPDY_SPDY_FRAME_READ;
            }
        }
    }
    return status;
}

void sspdy_response_feed_data(serf_bucket_t *bkt,
                              serf_bucket_t *wrapped)
{
    spdy_data_ctx_t *ctx = bkt->data;

    ctx->wrapped = wrapped;
}

void sspdy_response_feed_frame(serf_bucket_t *bkt,
                               sspdy_data_frame_t *frame,
                               serf_bucket_t *wrapped)
{
    spdy_data_ctx_t *ctx = bkt->data;

    ctx->frame = frame;
    ctx->remaining = frame->hdr.length;

    sspdy_response_feed_data(bkt, wrapped);
}

const serf_bucket_type_t serf_bucket_type_spdy_in_data = {
    "IN/SPDY_DATA",
    sspdy_spdy_in_data_read,
    NULL,
};
