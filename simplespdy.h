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

#ifndef SIMPLE_SPDY_H
#define SIMPLE_SPDY_H

#include <apr.h>
#include <apr_pools.h>
#include <apr_uri.h>

#include "spdy_streams.h"

#define LOG 1


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

/* SPDY protocol */

apr_status_t
ssl_socket_read(void *baton, char *data, apr_size_t *len);

apr_status_t
ssl_socket_write(void *baton, const char *data, apr_size_t *len);

apr_status_t test(sspdy_stream_t *stream, apr_pool_t *pool);


#endif
