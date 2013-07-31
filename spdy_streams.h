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

#ifndef SPDY_STREAMS_H
#define SPDY_STREAMS_H

#include <apr_hash.h>

#include "types.h"

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

/* Simple stream */
extern const sspdy_stream_type_t sspdy_stream_type_simple;
apr_status_t sspdy_create_simple_stream(sspdy_stream_t **stream,
                                        const char *buf,
                                        apr_size_t len,
                                        apr_pool_t *pool);

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
apr_status_t
sspdy_create_spdy_in_data_stream(sspdy_stream_t **stream,
                                 sspdy_stream_t *wrapped,
                                 sspdy_data_frame_t *frame,
                                 apr_pool_t *pool);

#endif
