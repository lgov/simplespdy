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

#define BUFSIZE 1048576

typedef struct sspdy_proto_ctx_t
{
    apr_pool_t *pool;

    sspdy_stream_t *wrapped;

    sspdy_config_store_t *config_store;

    char *in_data;
    apr_size_t available;
    apr_size_t in_cur_pos;

    apr_int32_t streamid;
} sspdy_proto_ctx_t;

typedef enum {
    SPDY_CTRL_SYN_STREAM = 1,
    SPDY_CTRL_REPLY      = 2,
    SPDY_CTRL_RST_STREAM = 3,
    SPDY_CTRL_SETTINGS   = 4,
    SPDY_CTRL_GOAWAY     = 7,
} sspdy_ctrl_frame_type_t;

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

typedef struct sspdy_goaway_frame_t {
    spdy_frame_hdr_t hdr;

    frame_read_state_t state;

} sspdy_goaway_frame_t;

/* Read and consume REQUESTED nr of bytes. If the amount is not available,
 0 bytes are consumed. */
static apr_status_t
read_exact(sspdy_proto_ctx_t *ctx, apr_size_t requested, const char **data)
{
    if (ctx->available < requested)
        return APR_EAGAIN;

    *data = ctx->in_data + ctx->in_cur_pos;
    ctx->in_cur_pos += requested;
    ctx->available -= requested;

    return APR_SUCCESS;
}

static spdy_frame_hdr_t *
create_ctrl_frame_of_type(apr_uint16_t type,
                          apr_pool_t *pool)
{
    spdy_frame_hdr_t *hdr;

    switch(type) {
/*        case SPDY_CTRL_SYN_STREAM:
            break;
        case SPDY_CTRL_REPLY:
            break;
 */
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
        default:
            sspdy__log(LOG, __FILE__, "Unknown control frame type %d.\n", type);
            hdr = apr_palloc(pool, sizeof(spdy_frame_hdr_t));
            break;
    }

    hdr->control = 1;
    hdr->ctrl.type = type;

    return hdr;
}


typedef struct sspdy_data_frame_t {
    spdy_frame_hdr_t hdr;

    frame_read_state_t state;

} sspdy_data_frame_t;


static spdy_frame_hdr_t *
create_data_frame(apr_pool_t *pool)
{
    sspdy_data_frame_t *frame;
    spdy_frame_hdr_t *hdr;

    frame = apr_palloc(pool, sizeof(sspdy_data_frame_t));
    frame->state = SPDY_FRAME_INIT;
    hdr = (spdy_frame_hdr_t *)frame;
    hdr->control = 1;

    return hdr;
}

static apr_status_t
read_spdy_frame_hdr(spdy_frame_hdr_t **hdr, sspdy_proto_ctx_t *ctx,
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

        version = (*p++ << 8) + *p++;
        version &= 0x7fff;
        type = (*p++ << 8) + *p++;

        frame = create_ctrl_frame_of_type(type, pool);
        frame->ctrl.version = version;
        frame->ctrl.type = type;
    } else {
        frame = create_data_frame(pool);
        frame->data.streamid = (*p++ << 24) + (*p++ << 16) +
                               (*p++ << 8) + *p++;
        frame->data.streamid &= 0x7fffffff;
    }
    frame->flags = *p++;
    frame->length = (*p++ << 16) + (*p++ << 8) + *p++;

    if (frame->control)
        sspdy__log(LOG, __FILE__, "spdy control frame. version:%d, "
                   "type:%d, flags:%d, length:%d.\n",
                   frame->ctrl.version, frame->ctrl.type, frame->flags,
                   frame->length);
    else
        sspdy__log(LOG, __FILE__, "spdy data frame. id:%d, "
                       "flags:%d, length:%d\n", frame->data.streamid,
                       frame->flags, frame->length);

    *hdr = frame;

    return APR_SUCCESS;
}

typedef enum {
    SSPDY_FLAG_HDR_CLEAR_SETTINGS = 0x1,
} sspdy_header_flags_t;

typedef enum {
    SSPDY_FLAG_SETTINGS_PERSIST_VALUE = 0x1,
    SSPDY_FLAG_SETTINGS_PERSISTED     = 0x2,
} sspdy_settings_flags_t;

static apr_status_t
read_spdy_settings_frame(sspdy_proto_ctx_t *ctx, spdy_frame_hdr_t *hdr,
                         apr_pool_t *pool)
{
    const char *p;
    sspdy_settings_frame_t *frame = (sspdy_settings_frame_t *)hdr;
    apr_uint32_t nr_of_entries;
    apr_status_t status;

    sspdy__log(LOG, __FILE__, "Read settings frame.\n");
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
read_spdy_data_frame(sspdy_proto_ctx_t *ctx, spdy_frame_hdr_t *hdr,
                     apr_pool_t *pool)
{
    const char *p;
    sspdy_data_frame_t *frame = (sspdy_data_frame_t *)hdr;
    apr_status_t status;

    sspdy__log(LOG, __FILE__, "Read data frame.\n");
    if (frame->state == SPDY_FRAME_INIT) {

    }
    STATUSERR(read_exact(ctx, hdr->length, &p));

    return APR_SUCCESS;
}

static apr_status_t
read_spdy_rst_stream_frame(sspdy_proto_ctx_t *ctx, spdy_frame_hdr_t *hdr,
                           apr_pool_t *pool)
{
    const char *p;
    sspdy_data_frame_t *frame = (sspdy_data_frame_t *)hdr;
    apr_status_t status;

    sspdy__log(LOG, __FILE__, "Read rst_stream frame.\n");
    if (frame->state == SPDY_FRAME_INIT) {

    }
    STATUSERR(read_exact(ctx, hdr->length, &p));

    return APR_SUCCESS;
}

static apr_status_t
read_spdy_goaway_frame(sspdy_proto_ctx_t *ctx, spdy_frame_hdr_t *hdr,
                       apr_pool_t *pool)
{
    const char *p;
    sspdy_data_frame_t *frame = (sspdy_goaway_frame_t *)hdr;
    apr_status_t status;

    sspdy__log(LOG, __FILE__, "Read goaway frame.\n");
    if (frame->state == SPDY_FRAME_INIT) {

    }
    STATUSERR(read_exact(ctx, hdr->length, &p));

    return APR_SUCCESS;
}

static apr_status_t
read_spdy_frame(apr_size_t *remaining,
                sspdy_proto_ctx_t *ctx, spdy_frame_hdr_t *hdr,
                apr_pool_t *pool)
{
    apr_status_t status;

    if (hdr->control) {
        switch(hdr->ctrl.type) {
/*            case SPDY_CTRL_SYN_STREAM:
                break;
            case SPDY_CTRL_REPLY:
                break;*/
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

apr_status_t
sspdy_create_spdy_proto_stream(sspdy_config_store_t *config_store,
                               sspdy_stream_t **stream,
                               sspdy_stream_t *wrapped,
                               apr_pool_t *pool)
{
    sspdy_proto_ctx_t *ctx;

    ctx = apr_pcalloc(pool, sizeof(sspdy_proto_ctx_t));
    ctx->wrapped = wrapped;
    ctx->pool = pool;
    ctx->config_store = config_store;
    ctx->in_data = apr_palloc(pool, BUFSIZE);
    ctx->streamid = 1; /* odd number for client-initiated streams */

    *stream = apr_palloc(pool, sizeof(sspdy_stream_t));
    (*stream)->type = &sspdy_stream_type_spdy_proto;
    (*stream)->data = ctx;

    return APR_SUCCESS;
}

/* Ensure that the buffer contains REQUESTED # of bytes, are as close as
   possible. */
static apr_status_t
ensure_bytes(sspdy_proto_ctx_t *ctx, sspdy_stream_t *wrapped,
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
    memcpy(ctx->in_data + ctx->in_cur_pos + ctx->available, frdata, frlen);
    ctx->available += frlen;

    if (ctx->available >= requested) {
        *len = requested;
        return status;
    }

    *len = ctx->available;

    return status;
}

apr_status_t sspdy_spdy_proto_read(sspdy_stream_t *stream, apr_size_t requested,
                                   const char **data, apr_size_t *len)
{
    sspdy_proto_ctx_t *ctx = stream->data;
    spdy_frame_hdr_t *hdr;
    const char *frdata;
    apr_size_t frlen, remaining;
    apr_status_t status;

    *len = 0;

    STATUSREADERR(ensure_bytes(ctx, ctx->wrapped, 8, &frlen));

    if (!frlen)
        return status;

    STATUSERR(read_spdy_frame_hdr(&hdr, ctx, ctx->pool));

    STATUSREADERR(ensure_bytes(ctx, ctx->wrapped, hdr->length, &frlen));

    STATUSERR(read_spdy_frame(&remaining, ctx, hdr, ctx->pool));

    return status;
}

#define MAX_STREAMID 0x7FFFFFFF

static apr_status_t
next_streamid(apr_int32_t *streamid, sspdy_proto_ctx_t *ctx)
{
    if (ctx->streamid > MAX_STREAMID)
        return SSPDY_SPDY_MAXIMUM_STREAMID;

    *streamid = ctx->streamid;
    ctx->streamid += 2; /* next id, always odd numbers for client-initiated
                           streams */
    return APR_SUCCESS;
}

#define WRITE_INT32(p, nr)\
    *p++ = (nr >> 24) & 0xff;\
    *p++ = (nr >> 16) & 0xff;\
    *p++ = (nr >> 8) & 0xff;\
    *p++ = (nr) & 0xff;

#define WRITE_INT24(p, nr)\
    *p++ = (nr >> 16) & 0xff;\
    *p++ = (nr >> 8) & 0xff;\
    *p++ = (nr) & 0xff;

static apr_status_t
create_compressed_header_block(sspdy_proto_ctx_t *ctx, const char **data,
                               apr_int32_t *len, apr_pool_t *pool)
{
    apr_int32_t nr_of_hdrs = 1;
    const char *hdr = "Host";
    const char *value = "lgo:ubuntu1:443";
    apr_int32_t length;
    char *buf = apr_palloc(pool, 4096);
    char *p = buf;

    WRITE_INT32(p, nr_of_hdrs);

    length = strlen(hdr);
    WRITE_INT32(p, length);
    memcpy(p, hdr, length);
    p += length;

    length = strlen(value);
    WRITE_INT32(p, length);
    memcpy(p, value, length);
    p += length;

    *len = p - buf;
    *data = buf;

    return APR_SUCCESS;
}

static apr_status_t
write_spdy_data_frame(sspdy_proto_ctx_t *ctx, const char *data, apr_size_t *len,
                      apr_pool_t *pool)
{
    char buf[1024];
    char *p = buf;
    const char *hdrs;
    apr_size_t total_length;
    apr_int32_t streamid, length, hdrs_len;
    apr_pool_t *tmp_pool;
    apr_status_t status;

    STATUSERR(next_streamid(&streamid, ctx));

    STATUSERR(apr_pool_create(&tmp_pool, pool));
    STATUSERR(create_compressed_header_block(ctx, &hdrs, &hdrs_len, tmp_pool));

    length = 10 + hdrs_len;
    *len = length + 8;

    /* SYN_STREAM */
    *p++ = 0x80; /* Control bit and Version*/
    *p++ = 0x03;
    *p++ = 0x00; /* SYN_STREAM */
    *p++ = 0x01;

    *p++ = 0x00; /* Flags */

    WRITE_INT24(p, length);

    WRITE_INT32(p, streamid & 0x7fffffff); /* first bit isn't used */

    WRITE_INT32(p, 0 & 0x7fffffff); /* Associated Stream ID */

    *p++ = 0x00; /* Priority and Unused */
    *p++ = 0x00; /* Slot */

    memcpy(p, hdrs, hdrs_len);

    status = sspdy_stream_write(ctx->wrapped, buf, len);

    apr_pool_destroy(tmp_pool);

    return status;
}

apr_status_t sspdy_spdy_proto_write(sspdy_stream_t *stream,
                                    const char *data, apr_size_t *len)
{
    sspdy_proto_ctx_t *ctx = stream->data;
    apr_status_t status;

    STATUSERR(write_spdy_data_frame(ctx, data, len, ctx->pool));

    return status;
}

const sspdy_stream_type_t sspdy_stream_type_spdy_proto = {
    "SPDYPROTO",
    sspdy_spdy_proto_read,
    sspdy_spdy_proto_write,
};
