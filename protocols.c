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

#include "protocols.h"


apr_status_t sspdy_proto_data_available(sspdy_protocol_t *proto,
                                        serf_bucket_t *wrapped)
{
    return proto->type->data_available(proto, wrapped);
}

apr_status_t sspdy_proto_queue_request(sspdy_protocol_t *proto,
                                       int priority,
                                       void *setup_baton)
{
    return proto->type->queue_request(proto, priority, setup_baton);
}

apr_status_t sspdy_proto_read(sspdy_protocol_t *proto, apr_size_t requested,
                              const char **data, apr_size_t *len)
{
    return proto->type->read(proto, requested, data, len);
}

apr_status_t
sspdy_create_request(sspdy_request_t **out_request, int priority,
                     void *setup_baton,
                     apr_pool_t *pool)
{
    sspdy_request_t *request = apr_pcalloc(pool, sizeof(sspdy_request_t));

    request->bkt_alloc = serf_bucket_allocator_create(pool, NULL, NULL);
    request->hdrs = serf_bucket_headers_create(request->bkt_alloc);
    request->priority = priority;
    request->setup_baton = setup_baton;

    *out_request = request;

    return APR_SUCCESS;
}

void
sspdy_set_header(sspdy_request_t *request, const char *hdr, const char *value)
{
    serf_bucket_headers_setn(request->hdrs, hdr, value);
}
