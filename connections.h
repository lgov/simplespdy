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

#ifndef CONNECTIONS_H
#define CONNECTIONS_H

#include <apr.h>
#include <apr_pools.h>
#include <apr_poll.h>

#include "config_store.h"

/* SSL */
typedef struct ssl_context_t ssl_context_t;

ssl_context_t *init_ssl(apr_pool_t *pool, const char *proto,
                        apr_socket_t *skt, const char *hostname);

/***************************/
/* Connection declarations */
/***************************/
typedef struct sspdy_connection_type_t sspdy_connection_type_t;

typedef struct sspdy_connection_t {
    /** the type of this connection */
    const sspdy_connection_type_t *type;

    /** private data */
    void *data;
} sspdy_connection_t;

struct sspdy_connection_type_t {
    const char *name;

    apr_status_t (*read)(sspdy_connection_t *conn, apr_size_t requested,
                         const char **data, apr_size_t *len);

    /* write */
    apr_status_t (*write)(sspdy_connection_t *conn, const char *data,
                          apr_size_t *len);

    apr_status_t (*update_pollset)(sspdy_connection_t *conn, apr_pollset_t *ps);

    void (*destroy)(sspdy_connection_t *conn);
};

apr_status_t sspdy_connection_read(sspdy_connection_t *conn,
                                   apr_size_t requested,
                                   const char **data, apr_size_t *len);
apr_status_t sspdy_connection_write(sspdy_connection_t *conn, const char *data,
                                    apr_size_t *len);
apr_status_t sspdy_connection_update_pollset(sspdy_connection_t *conn,
                                             apr_pollset_t *pollset);

/* SSL/TLS connection */
extern const sspdy_connection_type_t sspdy_connection_type_tls;

apr_status_t sspdy_create_tls_connection(sspdy_connection_t **,
                                         sspdy_config_store_t *config_store,
                                         const char *hostname, apr_port_t port,
                                         apr_pool_t *pool);

apr_status_t
ssl_socket_read(void *baton, char *data, apr_size_t *len);

apr_status_t
ssl_socket_write(void *baton, const char *data, apr_size_t *len);


#endif