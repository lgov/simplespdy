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
#include "protocols.h"
#include "config_store.h"

#include <apr_hash.h>

#define BUFSIZE 1048576
#define SPDY_FRAME_SIZE 0xffffff


/* Read and consume REQUESTED nr of bytes. If the amount is not available,
 0 bytes are consumed. */
static apr_status_t
read_exact(spdy_proto_ctx_t *ctx, apr_size_t requested, const char **data)
{
    if (ctx->available < requested)
        return APR_EAGAIN;

    if (requested <= ctx->vec[ctx->in_iov_pos].iov_len - ctx->in_cur_pos) {
        *data = ctx->vec[ctx->in_iov_pos].iov_base + ctx->in_cur_pos;
        ctx->in_cur_pos += requested;
        ctx->available -= requested;
    } else
        return APR_EGENERAL;

    if (ctx->vec[ctx->in_iov_pos].iov_len &&
        ctx->in_cur_pos == ctx->vec[ctx->in_iov_pos].iov_len) {

        ctx->in_iov_pos++;
        ctx->in_cur_pos = 0;
    }

    return APR_SUCCESS;
}

static apr_status_t
read_compressed_header_block(spdy_proto_ctx_t *ctx, spdy_frame_hdr_t *frame_hdr,
                             apr_pool_t *pool)
{
    const char *p;
    sspdy_settings_frame_t *frame = (sspdy_settings_frame_t *)frame_hdr;
    apr_uint32_t nr_of_hdrs;
    const char *data;
    apr_size_t len;
    const char *hdr, *val;
    int i;
    apr_status_t status;


    if (frame->state == SPDY_FRAME_INIT) {
        const char *compressed;
        STATUSERR(read_exact(ctx, frame_hdr->length - 4, &compressed));
        STATUSERR(decompressbuf(&p, &len, ctx->z_ctx,
                                compressed, frame_hdr->length,
                                pool));
        READ_INT32(p, nr_of_hdrs);
    }

    for (i = 0; i < nr_of_hdrs; i++) {
        apr_uint32_t length;

        /* Read header */
        READ_INT32(p, length);
        hdr = p;
/*        memcpy(hdr, p, length); */
        p += length;

        /* Read value */
        READ_INT32(p, length);
        val = p;
/*        memcpy(val, p, length); */
        p += length;

        sspdy__log(LOG, __FILE__, "Read header %s with value %s.\n", hdr, val);
    }

    return APR_SUCCESS;
}

static spdy_frame_hdr_t *
create_ctrl_frame_of_type(apr_uint16_t type,
                          apr_pool_t *pool)
{
    spdy_frame_hdr_t *hdr;

    switch(type) {
/*        case SPDY_CTRL_SYN_STREAM:
            break; */
        case SPDY_CTRL_REPLY:
            {
                sspdy_syn_reply_frame_t *frame;
                frame = apr_palloc(pool, sizeof(sspdy_syn_reply_frame_t));
                frame->state = SPDY_FRAME_INIT;
                hdr = (spdy_frame_hdr_t *)frame;
            }
            break;

        case SPDY_CTRL_RST_STREAM:
            {
                sspdy_rst_stream_frame_t *frame;
                frame = apr_palloc(pool, sizeof(sspdy_rst_stream_frame_t));
                frame->state = SPDY_FRAME_INIT;
                hdr = (spdy_frame_hdr_t *)frame;
            }
            break;
        case SPDY_CTRL_SETTINGS:
            {
                sspdy_settings_frame_t *frame;
                frame = apr_palloc(pool, sizeof(sspdy_settings_frame_t));
                frame->state = SPDY_FRAME_INIT;
                hdr = (spdy_frame_hdr_t *)frame;
            }
            break;
        case SPDY_CTRL_GOAWAY:
            {
                sspdy_goaway_frame_t *frame;
                frame = apr_palloc(pool, sizeof(sspdy_goaway_frame_t));
                frame->state = SPDY_FRAME_INIT;
                hdr = (spdy_frame_hdr_t *)frame;
            }
            break;
        default:
            sspdy__log(LOG, __FILE__, "Unknown control frame type %d.\n", type);
            hdr = apr_palloc(pool, sizeof(spdy_frame_hdr_t));
            break;
    }

    hdr->control = 1;
    hdr->ctrl.type = type;

    return hdr;
}

static spdy_frame_hdr_t *
create_data_frame(apr_pool_t *pool)
{
    sspdy_data_frame_t *frame;
    spdy_frame_hdr_t *hdr;

    frame = apr_palloc(pool, sizeof(sspdy_data_frame_t));
    frame->state = SPDY_FRAME_INIT;
    hdr = (spdy_frame_hdr_t *)frame;
    hdr->control = 0;

    return hdr;
}

static apr_status_t
read_spdy_frame_hdr(spdy_frame_hdr_t **hdr, spdy_proto_ctx_t *ctx,
                    apr_pool_t *pool)
{
    spdy_frame_hdr_t *frame;
    const char *p;
    apr_byte_t control;
    apr_status_t status;

    STATUSERR(read_exact(ctx, 8, &p));

    frame = apr_palloc(ctx->pool, sizeof(spdy_frame_hdr_t));

    /* spdy specific, http/2.0 uses a different layout. */
    control = (*p & 0x80) >> 7;
    if (control) {
        apr_uint16_t version;
        apr_uint16_t type;

        READ_INT16(p, version);
        version &= 0x7fff;
        READ_INT16(p, type);

        frame = create_ctrl_frame_of_type(type, pool);
        frame->ctrl.version = version;
        frame->ctrl.type = type;
    } else {
        frame = create_data_frame(pool);

        READ_INT32(p, frame->data.streamid);
        frame->data.streamid &= 0x7fffffff;
    }
    READ_INT8(p, frame->flags);
    READ_INT24(p, frame->length);

    if (frame->control)
        sspdy__log(LOG, __FILE__, "spdy control frame. version:%d, "
                   "type:%d, flags:%d, length:%d.\n",
                   frame->ctrl.version, frame->ctrl.type, frame->flags,
                   frame->length);
    else
        sspdy__log(LOG, __FILE__, "spdy data frame. streamid:0x%x, "
                       "flags:%d, length:%d\n", frame->data.streamid,
                       frame->flags, frame->length);

    *hdr = frame;

    return APR_SUCCESS;
}

typedef enum {
    SSPDY_FLAG_SETTINGS_PERSIST_VALUE = 0x1,
    SSPDY_FLAG_SETTINGS_PERSISTED     = 0x2,
} sspdy_settings_flags_t;

static apr_status_t
read_spdy_settings_frame(spdy_proto_ctx_t *ctx, spdy_frame_hdr_t *hdr,
                         apr_pool_t *pool)
{
    const char *p;
    sspdy_settings_frame_t *frame = (sspdy_settings_frame_t *)hdr;
    apr_uint32_t nr_of_entries;
    apr_status_t status;

    sspdy__log(LOG, __FILE__, "Read SETTINGS frame.\n");
    if (frame->state == SPDY_FRAME_INIT) {
        /* Read the number of entries */
        STATUSERR(read_exact(ctx, 4, &p));

        frame->nr_of_entries = (*p++ << 24) + (*p++ << 16) + (*p++ << 8) + *p++;

        if (frame->hdr.flags & SSPDY_FLAG_HDR_CLEAR_SETTINGS) {
            /* Remove all persisted settings */

            /* TODO */
        }
    }

    nr_of_entries = frame->nr_of_entries;
    frame->state = SPDY_FRAME_INPROGRESS;

    /* Current data should point to a ID/Value pair (not necessarily the first).
     */
    while (nr_of_entries) {
        apr_byte_t flags;
        apr_uint32_t uid, value;

        STATUSERR(read_exact(ctx, 8, &p));

        flags = *p++;
        uid = (*p++ << 16) + (*p++ << 8) + *p++;
        value = (*p++ << 24) + (*p++ << 16) + (*p++ << 8) + *p++;

        sspdy__log(LOG, __FILE__, "Read setting uid: %d value: %d.\n",
                   uid, value);

        if (flags & SSPDY_FLAG_SETTINGS_PERSIST_VALUE) {

        } else {

        }

        nr_of_entries--;
    }

    if (nr_of_entries == 0)
        frame->state = SPDY_FRAME_FINISHED;

    return APR_SUCCESS;
}

static apr_status_t
read_spdy_data_frame(spdy_proto_ctx_t *ctx, spdy_frame_hdr_t *hdr,
                     apr_pool_t *pool)
{
    const char *p;
    sspdy_data_frame_t *frame = (sspdy_data_frame_t *)hdr;
    apr_status_t status;

    sspdy__log(LOG, __FILE__, "Read DATA frame.\n");
    if (frame->state == SPDY_FRAME_INIT) {

    }
    STATUSERR(read_exact(ctx, hdr->length, &p));
    sspdy__log(LOG, __FILE__, "   data: '%.*s'\'\n", hdr->length, p);

    return APR_SUCCESS;
}

static apr_status_t
read_spdy_rst_stream_frame(spdy_proto_ctx_t *ctx, spdy_frame_hdr_t *hdr,
                           apr_pool_t *pool)
{
    const char *p;
    sspdy_data_frame_t *frame = (sspdy_data_frame_t *)hdr;
    apr_status_t status;

    sspdy__log(LOG, __FILE__, "Read RST_STREAM frame.\n");
    if (frame->state == SPDY_FRAME_INIT) {

    }
    STATUSERR(read_exact(ctx, hdr->length, &p));

    return APR_SUCCESS;
}

static apr_status_t
read_spdy_syn_reply_frame(spdy_proto_ctx_t *ctx, spdy_frame_hdr_t *hdr,
                          apr_pool_t *pool)
{
    const char *p;
    sspdy_syn_reply_frame_t *frame = (sspdy_syn_reply_frame_t *)hdr;
    apr_status_t status;

    sspdy__log(LOG, __FILE__, "Read SYN_REPLY frame.\n");
    if (frame->state == SPDY_FRAME_INIT) {
        STATUSERR(read_exact(ctx, 4, &p));

        READ_INT32(p, frame->streamid);
        frame->streamid &= 0x7fffffff;
    }
    sspdy__log(LOG, __FILE__, "  streamid: 0x%x.\n", frame->streamid);

    if (hdr->length > 4)
        STATUSERR(read_compressed_header_block(ctx, hdr, pool));

    return APR_SUCCESS;
}

static apr_status_t
read_spdy_goaway_frame(spdy_proto_ctx_t *ctx, spdy_frame_hdr_t *hdr,
                       apr_pool_t *pool)
{
    const char *p;
    sspdy_goaway_frame_t *frame = (sspdy_goaway_frame_t *)hdr;
    apr_status_t status;

    sspdy__log(LOG, __FILE__, "Read GOAWAY frame.\n");
    if (frame->state == SPDY_FRAME_INIT) {

    }

    if (hdr->length != 8) {
        sspdy__log(LOG, __FILE__, "Client side protocol error.\n");
        return SSPDY_SPDY_PROTOCOL_ERROR;
    }

    STATUSERR(read_exact(ctx, 8, &p));

    READ_INT32(p, frame->last_good_streamid);
    frame->last_good_streamid &= 0x7fffffff;

    READ_INT32(p, frame->status_code);

    switch (frame->status_code) {
        case SPDY_STATUS_PROTOCOL_ERROR:
            sspdy__log(LOG, __FILE__, "Server reported a protocol error.\n");
            break;
        case SPDY_STATUS_INTERNAL_ERROR:
            sspdy__log(LOG, __FILE__, "Server reported a protocol error.\n");
            break;
    }

    return APR_SUCCESS;
}

static apr_status_t
read_spdy_frame(apr_size_t *remaining,
                spdy_proto_ctx_t *ctx, spdy_frame_hdr_t *hdr,
                apr_pool_t *pool)
{
    apr_status_t status;

    if (hdr->control) {
        switch(hdr->ctrl.type) {
/*            case SPDY_CTRL_SYN_STREAM:
                break; */
            case SPDY_CTRL_REPLY:
                read_spdy_syn_reply_frame(ctx, hdr, pool);
                break;
            case SPDY_CTRL_RST_STREAM:
                read_spdy_rst_stream_frame(ctx, hdr, pool);
                break;
            case SPDY_CTRL_SETTINGS:
                read_spdy_settings_frame(ctx, hdr, pool);
                break;
            case SPDY_CTRL_GOAWAY:
                read_spdy_goaway_frame(ctx, hdr, pool);
                break;
            default:
                ctx->in_cur_pos += hdr->length;
                ctx->available -= hdr->length;
                break;
        }
    } else {
        read_spdy_data_frame(ctx, hdr, pool);
    }

    return APR_SUCCESS;
}

#if 0
/* Ensure that the buffer contains REQUESTED # of bytes, are as close as
   possible. */
static apr_status_t
ensure_bytes(spdy_proto_ctx_t *ctx, sspdy_stream_t *wrapped,
             apr_size_t requested, apr_size_t *len)
{
    apr_size_t frlen;
    const char *frdata;
    apr_status_t status;

    if (requested > BUFSIZE)
        requested = BUFSIZE;

    if (ctx->available >= requested) {
        *len = requested;
        return APR_SUCCESS;
    }

    STATUSREADERR(sspdy_stream_read(wrapped, requested - ctx->available,
                                    &frdata, &frlen));

    /* Append this data to the end of the buffer */
    memcpy((char*)ctx->in_data + ctx->in_cur_pos + ctx->available, frdata, frlen);
    ctx->available += frlen;

    if (ctx->available >= requested) {
        *len = requested;
        return status;
    }

    *len = ctx->available;

    return status;
}
#endif

apr_status_t compact_and_copy(sspdy_protocol_t *proto, apr_pool_t *pool)
{
    spdy_proto_ctx_t *ctx = proto->data;
    char *cur, *data;
    int i;


    if (ctx->available == 0) {
        for (i = 0; i < ctx->vec_len; i++) {
            ctx->vec[i].iov_len = 0;
            ctx->vec[i].iov_base = NULL;
        }
        ctx->in_cur_pos = 0;
        ctx->vec_len = 0;
        ctx->in_iov_pos = 0;

        return APR_SUCCESS;
    }

    if (ctx->vec_len == 1)
        return APR_SUCCESS;

    data = apr_palloc(pool, ctx->available);

    cur = data;
    for (i = 0; i < ctx->in_iov_pos; i++) {
        ctx->vec[i].iov_len = 0;
        ctx->vec[i].iov_base = NULL;
    }
    for (i = ctx->in_iov_pos; i < ctx->vec_len; i++) {
        memcpy(cur, ctx->vec[i].iov_base + ctx->in_cur_pos,
               ctx->vec[i].iov_len - ctx->in_cur_pos);
        cur += (ctx->vec[i].iov_len - ctx->in_cur_pos);
        ctx->vec[i].iov_len = 0;
        ctx->vec[i].iov_base = NULL;
        ctx->in_cur_pos = 0;
    }
    ctx->vec[0].iov_base = data;
    ctx->vec[0].iov_len = ctx->available;
    ctx->vec_len = 1;
    ctx->in_iov_pos = 0;

    return APR_SUCCESS;
}


#if 0
apr_status_t test(sspdy_stream_t *stream, apr_pool_t *pool)
{
    const char *data;
    apr_uint32_t len;
    spdy_frame_hdr_t *hdr;
    const char syn_reply_hdr[] = { 0x80, 0x03, 0x00, 0x02, 0x00, 0x00,
        0x00, 0xff, 0x00, 0x00, 0x00, 0x02 };
    apr_status_t status;

    spdy_proto_ctx_t *ctx = stream->data;

    STATUSERR(create_compressed_header_block(ctx, &data, &len, pool));

    ctx->vec[0].iov_base = (void *)syn_reply_hdr;
    ctx->vec[0].iov_len = 12;
    ctx->vec_len = 1;
    ctx->available = ctx->vec[0].iov_len;

    STATUSERR(read_spdy_frame_hdr(&hdr, ctx, ctx->pool));

    ctx->vec[0].iov_base = (void *)data;
    ctx->vec[0].iov_len = len;
    ctx->vec_len = 1;
    ctx->available = ctx->vec[0].iov_len;
    ctx->in_cur_pos = 0;
    hdr->length = len;

    STATUSERR(read_compressed_header_block(ctx, hdr, pool));

    return APR_SUCCESS;
}
#endif

apr_status_t
sspdy_create_spdy_tls_protocol(sspdy_protocol_t **proto,
                               sspdy_config_store_t *config_store,
                               apr_pool_t *pool)
{
    spdy_proto_ctx_t *ctx;
    apr_status_t status;

    ctx = apr_pcalloc(pool, sizeof(spdy_proto_ctx_t));
    ctx->pool = pool;
    ctx->config_store = config_store;
    ctx->streamid = 1; /* odd number for client-initiated streams */
    ctx->frame_buf = apr_palloc(pool, SPDY_FRAME_SIZE);

    STATUSERR(init_compression(&ctx->z_ctx, ctx->pool));

    *proto = apr_palloc(pool, sizeof(sspdy_protocol_t));
    (*proto)->type = &sspdy_protocol_type_spdy;
    (*proto)->data = ctx;

    return APR_SUCCESS;
}

apr_status_t
sspdy_spdy_proto_queue_request(sspdy_protocol_t *proto,
                               sspdy_setup_request_func_t setup_request,
                               void *setup_baton)
{
    spdy_proto_ctx_t *ctx = proto->data;

    spdy_request_t *req = apr_palloc(ctx->pool, sizeof(spdy_request_t));
    req->setup_baton = setup_baton;
    req->setup_request = setup_request;
    req->written = 0;

    /* Add to queue */
    ctx->req = req;

    return APR_SUCCESS;
}

static apr_status_t
sspdy_spdy_proto_read(sspdy_protocol_t *proto, apr_size_t requested,
                      const char **data, apr_size_t *len)
{
    spdy_proto_ctx_t *ctx = proto->data;
    sspdy_stream_t *syn_stream;
    apr_status_t status;

    if (ctx->req && !ctx->req->written) {
        ctx->req->setup_request(ctx->req->setup_baton,
                                &ctx->req->handle_response,
                                data, len);
        ctx->req->written = 1;

        /* create a SYN_STREAM frame */
        STATUSERR(sspdy_create_spdy_out_syn_stream(&syn_stream, ctx,
                                                   NULL, ctx->pool));
        /* create a DATA frame */


        status = sspdy_stream_read(syn_stream, requested, data, len);

        return status;
    }

    *len = 0;

    return APR_EOF;
}

apr_status_t sspdy_spdy_proto_data_available(sspdy_protocol_t *proto,
                                             const char *data, apr_size_t len)
{
    spdy_proto_ctx_t *ctx = proto->data;
    spdy_frame_hdr_t *hdr;
    const char *frdata;
    apr_size_t frlen, remaining;
    apr_status_t status;
    int current_msg_in_progress = 0;

    ctx->vec[ctx->vec_len].iov_base = (void *)data;
    ctx->vec[ctx->vec_len].iov_len = len;
    ctx->available += len;
    ctx->vec_len++;

    if (!ctx->header_read) {
        sspdy__log(LOG, __FILE__,
                   "proto_data_available, new header available: %d bytes.\n",
                   len + ctx->available);

        /* compact_and_copy */

        STATUSERR(read_spdy_frame_hdr(&hdr, ctx, ctx->pool));

        ctx->header_read = 1;
        ctx->hdr = hdr;
    } else {
        hdr = ctx->hdr;
    }

    if (hdr->control) {
        STATUSERR(read_spdy_frame(&remaining, ctx, hdr, ctx->pool));
        ctx->header_read = 0;
    } else {
        sspdy_stream_t *stream;
        sspdy_stream_t *wrapped;
        const char *buf = ctx->vec[ctx->in_iov_pos].iov_base + ctx->in_cur_pos;

        STATUSERR(sspdy_create_simple_stream(&wrapped,
                                             buf,
                                             ctx->available,
                                             ctx->pool));
        ctx->available = 0;
        ctx->in_iov_pos++;
        
        /* data frame */
        STATUSERR(sspdy_create_spdy_in_data_stream(&stream,
                                                   wrapped,
                                                   (sspdy_data_frame_t *)hdr,
                                                   ctx->pool));
        STATUSREADERR(ctx->req->handle_response(NULL, stream));
    }

    compact_and_copy(proto, ctx->pool);

    return status;
}

#if 0
apr_status_t sspdy_spdy_proto_write(sspdy_stream_t *stream,
                                    const char *data, apr_size_t *len)
{
    spdy_proto_ctx_t *ctx = stream->data;
    apr_status_t status;
    
    STATUSERR(write_spdy_data_frame(ctx, data, len, ctx->pool));
    
    return status;
}
#endif

const sspdy_protocol_type_t sspdy_protocol_type_spdy = {
    "SPDYPROTO",
    sspdy_spdy_proto_data_available,
    sspdy_spdy_proto_queue_request,
    sspdy_spdy_proto_read,
};
