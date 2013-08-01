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

#ifndef PROTOCOLS_H
#define PROTOCOLS_H

#include <apr.h>
#include <apr_pools.h>

#include "config_store.h"
#include "spdy_streams.h"

/*************************/
/* Protocol declarations */
/*************************/
typedef struct sspdy_protocol_type_t sspdy_protocol_type_t;

struct sspdy_protocol_t {
    /** the type of this protocol */
    const sspdy_protocol_type_t *type;

    /** private data */
    void *data;
};

typedef apr_status_t (*sspdy_handle_response_func_t)(void *baton,
                                                     sspdy_stream_t *stream);

typedef apr_status_t
(*sspdy_setup_request_func_t)(void *baton,
                              sspdy_handle_response_func_t *handle_response,
                              const char **data,
                              apr_size_t *len);

struct sspdy_protocol_type_t {
    const char *name;
    /*
     apr_status_t (*read)(sspdy_stream_t *stream, apr_size_t requested,
     const char **data, apr_size_t *len);
     */
    apr_status_t (*data_available)(sspdy_protocol_t *proto,
                                   sspdy_stream_t *wrapped);

    apr_status_t (*queue_request)(sspdy_protocol_t *proto,
                                  sspdy_setup_request_func_t setup_request,
                                  void *setup_baton);

    apr_status_t (*read)(sspdy_protocol_t *proto, apr_size_t requested,
                         const char **data, apr_size_t *len);

    void (*destroy)(sspdy_protocol_t *proto);
};

apr_status_t sspdy_proto_queue_request(sspdy_protocol_t *proto,
                                       sspdy_setup_request_func_t setup_request,
                                       void *setup_baton);
apr_status_t sspdy_proto_data_available(sspdy_protocol_t *proto,
                                        sspdy_stream_t *wrapped);
apr_status_t sspdy_proto_read(sspdy_protocol_t *proto, apr_size_t requested,
                              const char **data, apr_size_t *len);

/* HTTPS protocol */
apr_status_t sspdy_create_https_protocol(sspdy_protocol_t **,
                                         sspdy_config_store_t *config_store,
                                         apr_pool_t *pool);

typedef struct spdy_request_t {
    sspdy_setup_request_func_t setup_request;
    sspdy_handle_response_func_t handle_response;
    void *setup_baton;
    int written;
} spdy_request_t;

/* SPDY protocol */


#endif
