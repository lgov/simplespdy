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
#include "serf.h"

/* Buffered stream */
extern const serf_bucket_type_t sspdy_bucket_type_buffered;

typedef apr_status_t (*readfunc_t)(void *baton, char *data, apr_size_t *len);

typedef apr_status_t (*writefunc_t)(void *baton, const char *data,
apr_size_t *len);

/* BUFFERED */
apr_status_t
sspdy_create_buf_bucket(serf_bucket_t **bkt,
                        readfunc_t read, writefunc_t write, void *baton,
                        apr_pool_t *pool);

apr_status_t sspdy_buf_write(serf_bucket_t *bkt,
                             const char *data, apr_size_t *new_len);

/* SPDY OUT/SYN_STREAM */
extern const serf_bucket_type_t serf_bucket_type_out_syn;

apr_status_t sspdy_create_spdy_out_syn_bucket(serf_bucket_t **bkt,
                                              spdy_proto_ctx_t *spdy_ctx,
                                              apr_hash_t *hdrs,
                                              apr_pool_t *pool);

/* SPDY IN/DATA */
extern const serf_bucket_type_t serf_bucket_type_spdy_in_data;
apr_status_t
sspdy_create_response_bucket(serf_bucket_t **bkt,
                             apr_pool_t *pool);
void sspdy_response_feed_data(serf_bucket_t *bkt,
                              serf_bucket_t *wrapped);
void sspdy_response_feed_frame(serf_bucket_t *bkt,
                               sspdy_data_frame_t *frame,
                               serf_bucket_t *wrapped);

#endif
