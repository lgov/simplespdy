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

#include <zlib.h>

const unsigned char SPDY_dictionary_txt[] = {
	0x00, 0x00, 0x00, 0x07, 0x6f, 0x70, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x00, 0x00, 0x00, 0x04, 0x68,
	0x65, 0x61, 0x64, 0x00, 0x00, 0x00, 0x04, 0x70,
	0x6f, 0x73, 0x74, 0x00, 0x00, 0x00, 0x03, 0x70,
	0x75, 0x74, 0x00, 0x00, 0x00, 0x06, 0x64, 0x65,
	0x6c, 0x65, 0x74, 0x65, 0x00, 0x00, 0x00, 0x05,
	0x74, 0x72, 0x61, 0x63, 0x65, 0x00, 0x00, 0x00,
	0x06, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x00,
	0x00, 0x00, 0x0e, 0x61, 0x63, 0x63, 0x65, 0x70,
	0x74, 0x2d, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65,
	0x74, 0x00, 0x00, 0x00, 0x0f, 0x61, 0x63, 0x63,
	0x65, 0x70, 0x74, 0x2d, 0x65, 0x6e, 0x63, 0x6f,
	0x64, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x00, 0x0f,
	0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x6c,
	0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x00,
	0x00, 0x00, 0x0d, 0x61, 0x63, 0x63, 0x65, 0x70,
	0x74, 0x2d, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x73,
	0x00, 0x00, 0x00, 0x03, 0x61, 0x67, 0x65, 0x00,
	0x00, 0x00, 0x05, 0x61, 0x6c, 0x6c, 0x6f, 0x77,
	0x00, 0x00, 0x00, 0x0d, 0x61, 0x75, 0x74, 0x68,
	0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x00, 0x00, 0x00, 0x0d, 0x63, 0x61, 0x63,
	0x68, 0x65, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x72,
	0x6f, 0x6c, 0x00, 0x00, 0x00, 0x0a, 0x63, 0x6f,
	0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x00, 0x00, 0x00, 0x0c, 0x63, 0x6f, 0x6e, 0x74,
	0x65, 0x6e, 0x74, 0x2d, 0x62, 0x61, 0x73, 0x65,
	0x00, 0x00, 0x00, 0x10, 0x63, 0x6f, 0x6e, 0x74,
	0x65, 0x6e, 0x74, 0x2d, 0x65, 0x6e, 0x63, 0x6f,
	0x64, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x00, 0x10,
	0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d,
	0x6c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65,
	0x00, 0x00, 0x00, 0x0e, 0x63, 0x6f, 0x6e, 0x74,
	0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67,
	0x74, 0x68, 0x00, 0x00, 0x00, 0x10, 0x63, 0x6f,
	0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x6f,
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00,
	0x00, 0x0b, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e,
	0x74, 0x2d, 0x6d, 0x64, 0x35, 0x00, 0x00, 0x00,
	0x0d, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
	0x2d, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x00, 0x00,
	0x00, 0x0c, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e,
	0x74, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x00, 0x00,
	0x00, 0x04, 0x64, 0x61, 0x74, 0x65, 0x00, 0x00,
	0x00, 0x04, 0x65, 0x74, 0x61, 0x67, 0x00, 0x00,
	0x00, 0x06, 0x65, 0x78, 0x70, 0x65, 0x63, 0x74,
	0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x70, 0x69,
	0x72, 0x65, 0x73, 0x00, 0x00, 0x00, 0x04, 0x66,
	0x72, 0x6f, 0x6d, 0x00, 0x00, 0x00, 0x04, 0x68,
	0x6f, 0x73, 0x74, 0x00, 0x00, 0x00, 0x08, 0x69,
	0x66, 0x2d, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x00,
	0x00, 0x00, 0x11, 0x69, 0x66, 0x2d, 0x6d, 0x6f,
	0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x2d, 0x73,
	0x69, 0x6e, 0x63, 0x65, 0x00, 0x00, 0x00, 0x0d,
	0x69, 0x66, 0x2d, 0x6e, 0x6f, 0x6e, 0x65, 0x2d,
	0x6d, 0x61, 0x74, 0x63, 0x68, 0x00, 0x00, 0x00,
	0x08, 0x69, 0x66, 0x2d, 0x72, 0x61, 0x6e, 0x67,
	0x65, 0x00, 0x00, 0x00, 0x13, 0x69, 0x66, 0x2d,
	0x75, 0x6e, 0x6d, 0x6f, 0x64, 0x69, 0x66, 0x69,
	0x65, 0x64, 0x2d, 0x73, 0x69, 0x6e, 0x63, 0x65,
	0x00, 0x00, 0x00, 0x0d, 0x6c, 0x61, 0x73, 0x74,
	0x2d, 0x6d, 0x6f, 0x64, 0x69, 0x66, 0x69, 0x65,
	0x64, 0x00, 0x00, 0x00, 0x08, 0x6c, 0x6f, 0x63,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00,
	0x0c, 0x6d, 0x61, 0x78, 0x2d, 0x66, 0x6f, 0x72,
	0x77, 0x61, 0x72, 0x64, 0x73, 0x00, 0x00, 0x00,
	0x06, 0x70, 0x72, 0x61, 0x67, 0x6d, 0x61, 0x00,
	0x00, 0x00, 0x12, 0x70, 0x72, 0x6f, 0x78, 0x79,
	0x2d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74,
	0x69, 0x63, 0x61, 0x74, 0x65, 0x00, 0x00, 0x00,
	0x13, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2d, 0x61,
	0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x05,
	0x72, 0x61, 0x6e, 0x67, 0x65, 0x00, 0x00, 0x00,
	0x07, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x72,
	0x00, 0x00, 0x00, 0x0b, 0x72, 0x65, 0x74, 0x72,
	0x79, 0x2d, 0x61, 0x66, 0x74, 0x65, 0x72, 0x00,
	0x00, 0x00, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65,
	0x72, 0x00, 0x00, 0x00, 0x02, 0x74, 0x65, 0x00,
	0x00, 0x00, 0x07, 0x74, 0x72, 0x61, 0x69, 0x6c,
	0x65, 0x72, 0x00, 0x00, 0x00, 0x11, 0x74, 0x72,
	0x61, 0x6e, 0x73, 0x66, 0x65, 0x72, 0x2d, 0x65,
	0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x00,
	0x00, 0x00, 0x07, 0x75, 0x70, 0x67, 0x72, 0x61,
	0x64, 0x65, 0x00, 0x00, 0x00, 0x0a, 0x75, 0x73,
	0x65, 0x72, 0x2d, 0x61, 0x67, 0x65, 0x6e, 0x74,
	0x00, 0x00, 0x00, 0x04, 0x76, 0x61, 0x72, 0x79,
	0x00, 0x00, 0x00, 0x03, 0x76, 0x69, 0x61, 0x00,
	0x00, 0x00, 0x07, 0x77, 0x61, 0x72, 0x6e, 0x69,
	0x6e, 0x67, 0x00, 0x00, 0x00, 0x10, 0x77, 0x77,
	0x77, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e,
	0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x00, 0x00,
	0x00, 0x06, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64,
	0x00, 0x00, 0x00, 0x03, 0x67, 0x65, 0x74, 0x00,
	0x00, 0x00, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75,
	0x73, 0x00, 0x00, 0x00, 0x06, 0x32, 0x30, 0x30,
	0x20, 0x4f, 0x4b, 0x00, 0x00, 0x00, 0x07, 0x76,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00,
	0x00, 0x08, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31,
	0x2e, 0x31, 0x00, 0x00, 0x00, 0x03, 0x75, 0x72,
	0x6c, 0x00, 0x00, 0x00, 0x06, 0x70, 0x75, 0x62,
	0x6c, 0x69, 0x63, 0x00, 0x00, 0x00, 0x0a, 0x73,
	0x65, 0x74, 0x2d, 0x63, 0x6f, 0x6f, 0x6b, 0x69,
	0x65, 0x00, 0x00, 0x00, 0x0a, 0x6b, 0x65, 0x65,
	0x70, 0x2d, 0x61, 0x6c, 0x69, 0x76, 0x65, 0x00,
	0x00, 0x00, 0x06, 0x6f, 0x72, 0x69, 0x67, 0x69,
	0x6e, 0x31, 0x30, 0x30, 0x31, 0x30, 0x31, 0x32,
	0x30, 0x31, 0x32, 0x30, 0x32, 0x32, 0x30, 0x35,
	0x32, 0x30, 0x36, 0x33, 0x30, 0x30, 0x33, 0x30,
	0x32, 0x33, 0x30, 0x33, 0x33, 0x30, 0x34, 0x33,
	0x30, 0x35, 0x33, 0x30, 0x36, 0x33, 0x30, 0x37,
	0x34, 0x30, 0x32, 0x34, 0x30, 0x35, 0x34, 0x30,
	0x36, 0x34, 0x30, 0x37, 0x34, 0x30, 0x38, 0x34,
	0x30, 0x39, 0x34, 0x31, 0x30, 0x34, 0x31, 0x31,
	0x34, 0x31, 0x32, 0x34, 0x31, 0x33, 0x34, 0x31,
	0x34, 0x34, 0x31, 0x35, 0x34, 0x31, 0x36, 0x34,
	0x31, 0x37, 0x35, 0x30, 0x32, 0x35, 0x30, 0x34,
	0x35, 0x30, 0x35, 0x32, 0x30, 0x33, 0x20, 0x4e,
	0x6f, 0x6e, 0x2d, 0x41, 0x75, 0x74, 0x68, 0x6f,
	0x72, 0x69, 0x74, 0x61, 0x74, 0x69, 0x76, 0x65,
	0x20, 0x49, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x32, 0x30, 0x34, 0x20,
	0x4e, 0x6f, 0x20, 0x43, 0x6f, 0x6e, 0x74, 0x65,
	0x6e, 0x74, 0x33, 0x30, 0x31, 0x20, 0x4d, 0x6f,
	0x76, 0x65, 0x64, 0x20, 0x50, 0x65, 0x72, 0x6d,
	0x61, 0x6e, 0x65, 0x6e, 0x74, 0x6c, 0x79, 0x34,
	0x30, 0x30, 0x20, 0x42, 0x61, 0x64, 0x20, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x34, 0x30,
	0x31, 0x20, 0x55, 0x6e, 0x61, 0x75, 0x74, 0x68,
	0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x34, 0x30,
	0x33, 0x20, 0x46, 0x6f, 0x72, 0x62, 0x69, 0x64,
	0x64, 0x65, 0x6e, 0x34, 0x30, 0x34, 0x20, 0x4e,
	0x6f, 0x74, 0x20, 0x46, 0x6f, 0x75, 0x6e, 0x64,
	0x35, 0x30, 0x30, 0x20, 0x49, 0x6e, 0x74, 0x65,
	0x72, 0x6e, 0x61, 0x6c, 0x20, 0x53, 0x65, 0x72,
	0x76, 0x65, 0x72, 0x20, 0x45, 0x72, 0x72, 0x6f,
	0x72, 0x35, 0x30, 0x31, 0x20, 0x4e, 0x6f, 0x74,
	0x20, 0x49, 0x6d, 0x70, 0x6c, 0x65, 0x6d, 0x65,
	0x6e, 0x74, 0x65, 0x64, 0x35, 0x30, 0x33, 0x20,
	0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x20,
	0x55, 0x6e, 0x61, 0x76, 0x61, 0x69, 0x6c, 0x61,
	0x62, 0x6c, 0x65, 0x4a, 0x61, 0x6e, 0x20, 0x46,
	0x65, 0x62, 0x20, 0x4d, 0x61, 0x72, 0x20, 0x41,
	0x70, 0x72, 0x20, 0x4d, 0x61, 0x79, 0x20, 0x4a,
	0x75, 0x6e, 0x20, 0x4a, 0x75, 0x6c, 0x20, 0x41,
	0x75, 0x67, 0x20, 0x53, 0x65, 0x70, 0x74, 0x20,
	0x4f, 0x63, 0x74, 0x20, 0x4e, 0x6f, 0x76, 0x20,
	0x44, 0x65, 0x63, 0x20, 0x30, 0x30, 0x3a, 0x30,
	0x30, 0x3a, 0x30, 0x30, 0x20, 0x4d, 0x6f, 0x6e,
	0x2c, 0x20, 0x54, 0x75, 0x65, 0x2c, 0x20, 0x57,
	0x65, 0x64, 0x2c, 0x20, 0x54, 0x68, 0x75, 0x2c,
	0x20, 0x46, 0x72, 0x69, 0x2c, 0x20, 0x53, 0x61,
	0x74, 0x2c, 0x20, 0x53, 0x75, 0x6e, 0x2c, 0x20,
	0x47, 0x4d, 0x54, 0x63, 0x68, 0x75, 0x6e, 0x6b,
	0x65, 0x64, 0x2c, 0x74, 0x65, 0x78, 0x74, 0x2f,
	0x68, 0x74, 0x6d, 0x6c, 0x2c, 0x69, 0x6d, 0x61,
	0x67, 0x65, 0x2f, 0x70, 0x6e, 0x67, 0x2c, 0x69,
	0x6d, 0x61, 0x67, 0x65, 0x2f, 0x6a, 0x70, 0x67,
	0x2c, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x2f, 0x67,
	0x69, 0x66, 0x2c, 0x61, 0x70, 0x70, 0x6c, 0x69,
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78,
	0x6d, 0x6c, 0x2c, 0x61, 0x70, 0x70, 0x6c, 0x69,
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78,
	0x68, 0x74, 0x6d, 0x6c, 0x2b, 0x78, 0x6d, 0x6c,
	0x2c, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c,
	0x61, 0x69, 0x6e, 0x2c, 0x74, 0x65, 0x78, 0x74,
	0x2f, 0x6a, 0x61, 0x76, 0x61, 0x73, 0x63, 0x72,
	0x69, 0x70, 0x74, 0x2c, 0x70, 0x75, 0x62, 0x6c,
	0x69, 0x63, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74,
	0x65, 0x6d, 0x61, 0x78, 0x2d, 0x61, 0x67, 0x65,
	0x3d, 0x67, 0x7a, 0x69, 0x70, 0x2c, 0x64, 0x65,
	0x66, 0x6c, 0x61, 0x74, 0x65, 0x2c, 0x73, 0x64,
	0x63, 0x68, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65,
	0x74, 0x3d, 0x75, 0x74, 0x66, 0x2d, 0x38, 0x63,
	0x68, 0x61, 0x72, 0x73, 0x65, 0x74, 0x3d, 0x69,
	0x73, 0x6f, 0x2d, 0x38, 0x38, 0x35, 0x39, 0x2d,
	0x31, 0x2c, 0x75, 0x74, 0x66, 0x2d, 0x2c, 0x2a,
	0x2c, 0x65, 0x6e, 0x71, 0x3d, 0x30, 0x2e
};

struct compress_ctx_t {
    z_stream zdestr;
    z_stream zinstr;

    apr_pool_t *pool;
};

apr_status_t
init_compression(compress_ctx_t **z_ctx, apr_pool_t *pool)
{
    z_stream zdestr, zinstr;
    compress_ctx_t *ctx;
    int zerr;

    ctx = apr_palloc(pool, sizeof(compress_ctx_t));
    ctx->pool = pool;

    /* zstream must be NULL'd out. */
    memset(&ctx->zdestr, 0, sizeof(z_stream));
    if (deflateInit(&ctx->zdestr, Z_DEFAULT_COMPRESSION) != Z_OK)
        return APR_EGENERAL;

    memset(&ctx->zinstr, 0, sizeof(z_stream));
    if (inflateInit(&ctx->zinstr) != Z_OK)
        return APR_EGENERAL;

    *z_ctx = ctx;

    return APR_SUCCESS;
}

apr_status_t
compressbuf(const char **data, apr_size_t *len,
            compress_ctx_t *z_ctx,
            const char* orig, apr_size_t orig_len,
            apr_pool_t *pool)
{
    int zerr;
    apr_size_t buf_size, write_len;
    void *write_buf;


#if 0
    deflateSetDictionary(&ctx->zdestr, (const Bytef *)SPDY_dictionary_txt,
                         sizeof(SPDY_dictionary_txt));
#endif


    /* The largest buffer we should need is 0.1% larger than the
       uncompressed data, + 12 bytes. This info comes from zlib.h.  */
    buf_size = orig_len + (orig_len / 1000) + 12 + sizeof(SPDY_dictionary_txt);

    write_buf = apr_palloc(pool, buf_size);

    z_ctx->zdestr.next_in = (Bytef *)orig;  /* Casting away const! */
    z_ctx->zdestr.avail_in = (uInt)orig_len;

    zerr = Z_OK;
    z_ctx->zdestr.next_out = write_buf;
    z_ctx->zdestr.avail_out = (uInt)buf_size;

    while (z_ctx->zdestr.avail_in > 0 && zerr != Z_STREAM_END)
    {
        apr_size_t compressed, available;

        available = z_ctx->zdestr.avail_out;
        zerr = deflate(&z_ctx->zdestr, Z_SYNC_FLUSH);
        if (zerr < 0)
            return APR_EGENERAL;

        compressed = available - z_ctx->zdestr.avail_out;
        z_ctx->zdestr.next_out += compressed;
    }

    *data = write_buf;
    *len = z_ctx->zdestr.total_out;

    return APR_SUCCESS;
}

apr_status_t
decompressbuf(const char **data, apr_size_t *len,
              compress_ctx_t *z_ctx,
              const char* orig, apr_size_t orig_len,
              apr_pool_t *pool)
{
    int zerr;
    apr_size_t buf_size, write_len;
    void *write_buf;

    z_ctx->zinstr.next_in = (Bytef *)orig;  /* Casting away const! */
    z_ctx->zinstr.avail_in = (uInt)orig_len;

    buf_size = orig_len * 3;
    write_buf = apr_palloc(pool, buf_size);

    zerr = Z_OK;
    z_ctx->zinstr.next_out = write_buf;
    z_ctx->zinstr.avail_out = (uInt)buf_size;

    while (z_ctx->zinstr.avail_in > 0 && zerr != Z_STREAM_END)
    {
        apr_size_t deflated, available;

        available = z_ctx->zinstr.avail_out;
        zerr = inflate(&z_ctx->zinstr, Z_SYNC_FLUSH);
        if (zerr < 0)
            return APR_EGENERAL;

        deflated = available - z_ctx->zinstr.avail_out;
        z_ctx->zinstr.next_out += deflated;
    }

    *data = write_buf;
    *len = z_ctx->zinstr.total_out;

    return APR_SUCCESS;
}
