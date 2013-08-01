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

/* Reads a 8 byte header. */
static apr_status_t
read_header_data(spdy_proto_ctx_t *ctx, serf_bucket_t *bkt,
                 const char **data)
{
    if (ctx->available == 8) {
        *data = ctx->hdr_data;
        ctx->available = 0;

        return APR_SUCCESS;
    }

    while (1) {
        apr_size_t len;
        int i;
        const char *ptr;
        apr_status_t status;

        STATUSREADERR(serf_bucket_read(bkt, 8 - ctx->available,
                                        data, &len));
        ptr = *data;
        for (i = 0; i < len; i++) {
            int pos = ctx->available + i;
            ctx->hdr_data[pos] = *ptr++;
        }
        ctx->available += len;
        *data = ctx->hdr_data;

        if (ctx->available == 8) {
            /* success */
            ctx->available = 0;
        }
            return status;
        if (status == APR_EOF || status == APR_EAGAIN)
            /* not enough data available */
            return status;
    }

    return APR_SUCCESS;
}

static apr_status_t
read_compressed_header_block(spdy_proto_ctx_t *ctx, spdy_frame_hdr_t *frame_hdr,
                             serf_bucket_t *bkt,
                             apr_pool_t *pool)
{
    const char *p;
    sspdy_settings_frame_t *frame = (sspdy_settings_frame_t *)frame_hdr;
    apr_uint32_t nr_of_hdrs;
    const char *data;
    const char *hdr, *val;
    int i;
    apr_status_t status;


    if (frame->state == SPDY_FRAME_INIT) {
        const char *compressed;
        apr_size_t len;

        /* Assume for now that all bytes are available */
        STATUSREADERR(serf_bucket_read(bkt, frame_hdr->length - 4,
                                        &compressed, &len));
        if (len < frame_hdr->length - 4)
            return APR_EGENERAL;

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
                    serf_bucket_t *bkt,
                    apr_pool_t *pool)
{
    spdy_frame_hdr_t *frame;
    const char *p;
    apr_byte_t control;
    apr_status_t status;

    *hdr = NULL;

    STATUSERR(read_header_data(ctx, bkt, &p));

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
                         serf_bucket_t *bkt,
                         apr_pool_t *pool)
{
    const char *p;
    sspdy_settings_frame_t *frame = (sspdy_settings_frame_t *)hdr;
    apr_uint32_t nr_of_entries;
    apr_status_t status;

    sspdy__log(LOG, __FILE__, "Read SETTINGS frame.\n");
    if (frame->state == SPDY_FRAME_INIT) {
        apr_size_t len;
        /* Read the number of entries */
        /* Assume for now that all bytes are available */
        STATUSREADERR(serf_bucket_read(bkt, 4, &p, &len));
        if (len < 4)
            return APR_EGENERAL;

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
        apr_byte_t id_flags;
        apr_size_t len;
        apr_uint32_t id, value;

        /* Assume for now that all bytes are available */
        STATUSREADERR(serf_bucket_read(bkt, 8, &p, &len));
        if (len < 8)
            return APR_EGENERAL;

        READ_INT8(p, id_flags);
        READ_INT24(p, id);
        READ_INT32(p, value);

        sspdy__log(LOG, __FILE__, "Read setting uid: %d value: %d.\n",
                   id, value);

        if (id_flags & SSPDY_FLAG_SETTINGS_PERSIST_VALUE) {

        } else {

        }

        nr_of_entries--;
    }

    if (nr_of_entries == 0)
        frame->state = SPDY_FRAME_FINISHED;

    return status;
}

static apr_status_t
read_spdy_data_frame(spdy_proto_ctx_t *ctx, spdy_frame_hdr_t *hdr,
                     serf_bucket_t *bkt,
                     apr_pool_t *pool)
{
    const char *p;
    sspdy_data_frame_t *frame = (sspdy_data_frame_t *)hdr;
    apr_size_t len;
    apr_status_t status;

    sspdy__log(LOG, __FILE__, "Read DATA frame.\n");
    if (frame->state == SPDY_FRAME_INIT) {

    }
    /* Assume for now that all bytes are available */
    STATUSREADERR(serf_bucket_read(bkt, hdr->length, &p, &len));
    if (len < hdr->length)
        return APR_EGENERAL;

    sspdy__log(LOG, __FILE__, "   data: '%.*s'\'\n", hdr->length, p);

    return status;
}

static apr_status_t
read_spdy_rst_stream_frame(spdy_proto_ctx_t *ctx, spdy_frame_hdr_t *hdr,
                           serf_bucket_t *bkt,
                           apr_pool_t *pool)
{
    const char *p;
    sspdy_data_frame_t *frame = (sspdy_data_frame_t *)hdr;
    apr_size_t len;
    apr_status_t status;

    sspdy__log(LOG, __FILE__, "Read RST_STREAM frame.\n");
    if (frame->state == SPDY_FRAME_INIT) {

    }

    /* Assume for now that all bytes are available */
    STATUSREADERR(serf_bucket_read(bkt, hdr->length, &p, &len));
    if (len < 8)
        return APR_EGENERAL;

    return status;
}

static apr_status_t
read_spdy_syn_reply_frame(spdy_proto_ctx_t *ctx, spdy_frame_hdr_t *hdr,
                          serf_bucket_t *bkt,
                          apr_pool_t *pool)
{
    const char *p;
    sspdy_syn_reply_frame_t *frame = (sspdy_syn_reply_frame_t *)hdr;
    apr_size_t len;
    apr_status_t status;

    sspdy__log(LOG, __FILE__, "Read SYN_REPLY frame.\n");
    if (frame->state == SPDY_FRAME_INIT) {
        /* Assume for now that all bytes are available */
        STATUSREADERR(serf_bucket_read(bkt, 4, &p, &len));
        if (len < 4)
            return APR_EGENERAL;

        READ_INT32(p, frame->streamid);
        frame->streamid &= 0x7fffffff;
    }
    sspdy__log(LOG, __FILE__, "  streamid: 0x%x.\n", frame->streamid);

    if (hdr->length > 4)
        STATUSERR(read_compressed_header_block(ctx, hdr, bkt, pool));

    return status;
}

static apr_status_t
read_spdy_goaway_frame(spdy_proto_ctx_t *ctx, spdy_frame_hdr_t *hdr,
                       serf_bucket_t *bkt,
                       apr_pool_t *pool)
{
    const char *p;
    sspdy_goaway_frame_t *frame = (sspdy_goaway_frame_t *)hdr;
    apr_size_t len;
    apr_status_t status;

    sspdy__log(LOG, __FILE__, "Read GOAWAY frame.\n");
    if (frame->state == SPDY_FRAME_INIT) {

    }

    if (hdr->length != 8) {
        sspdy__log(LOG, __FILE__, "Client side protocol error.\n");
        return SSPDY_SPDY_PROTOCOL_ERROR;
    }

    /* Assume for now that all bytes are available */
    STATUSREADERR(serf_bucket_read(bkt, 8, &p, &len));
    if (len < 8)
        return APR_EGENERAL;

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

    return status;
}

static apr_status_t
read_spdy_frame(apr_size_t *remaining,
                spdy_proto_ctx_t *ctx, spdy_frame_hdr_t *hdr,
                serf_bucket_t *bkt,
                apr_pool_t *pool)
{
    apr_status_t status;

    if (hdr->control) {
        switch(hdr->ctrl.type) {
/*            case SPDY_CTRL_SYN_STREAM:
                break; */
            case SPDY_CTRL_REPLY:
                status = read_spdy_syn_reply_frame(ctx, hdr, bkt, pool);
                break;
            case SPDY_CTRL_RST_STREAM:
                status = read_spdy_rst_stream_frame(ctx, hdr, bkt, pool);
                break;
            case SPDY_CTRL_SETTINGS:
                status = read_spdy_settings_frame(ctx, hdr, bkt, pool);
                break;
            case SPDY_CTRL_GOAWAY:
                status = read_spdy_goaway_frame(ctx, hdr, bkt, pool);
                break;
            default:
                ctx->in_cur_pos += hdr->length;
                ctx->available -= hdr->length;
                break;
        }
    } else {
        status = read_spdy_data_frame(ctx, hdr, bkt, pool);
    }

    return status;
}

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
    serf_bucket_t *req_bkt;
    apr_status_t status;

    if (ctx->req && !ctx->req->written) {
        ctx->req->setup_request(ctx->req->setup_baton,
                                &ctx->req->handle_response,
                                data, len);
        ctx->req->written = 1;

        /* create a SYN_STREAM frame */
        STATUSERR(sspdy_create_spdy_out_syn_bucket(&req_bkt, ctx,
                                                   NULL, ctx->pool));
        /* create a DATA frame */


        status = serf_bucket_read(req_bkt, requested, data, len);

        return status;
    }

    *len = 0;

    return APR_EOF;
}

apr_status_t sspdy_spdy_proto_data_available(sspdy_protocol_t *proto,
                                             serf_bucket_t *wrapped)
{
    spdy_proto_ctx_t *ctx = proto->data;
    spdy_frame_hdr_t *hdr;
    apr_size_t remaining;
    apr_status_t status = APR_SUCCESS;

    while (status == APR_SUCCESS) {
        if (!ctx->current_frame) {
            sspdy__log(LOG, __FILE__,
                       "proto_data_available, new header available.\n");

            STATUSREADERR(read_spdy_frame_hdr(&hdr, ctx, wrapped, ctx->pool));
            if (!hdr)
                return status;
        } else {
            hdr = ctx->current_frame;
        }

        if (hdr->control) {
            const char *data;
            apr_size_t len;

            STATUSREADERR(read_spdy_frame(&remaining, ctx, hdr, wrapped, ctx->pool));
            ctx->current_frame = NULL;
        } else {
            serf_bucket_t *response;
            const char *buf;

            /* find or create response bucket for this data frame */
            if (!ctx->current_response) {
                STATUSERR(sspdy_create_response_bucket(&response,
                                                       ctx->pool));
                ctx->current_response = response;
            } else {
                response = ctx->current_response;
            }

            /* Update the response */
            if (!ctx->current_frame) {
                sspdy_response_feed_frame(response, (sspdy_data_frame_t*)hdr,
                                          wrapped);
            } else {
                sspdy_response_feed_data(response, wrapped);
            }
            STATUSREADERR(ctx->req->handle_response(NULL, response));

            if (status == APR_EOF) {
                /* All data frames in this response where read. */
                ctx->current_frame = NULL;
                ctx->current_response = NULL;
            } else if (status == SSPDY_SPDY_FRAME_READ){
                /* This frame is finished, but the response isn't. */
                ctx->current_frame = NULL;
            } else
                /* This frame isn't finished */
                ctx->current_frame = hdr;
        }

        STATUSERR(status);
    }

    return status;
}

#if 0
apr_status_t sspdy_spdy_proto_write(serf_bucket_t *bkt,
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
