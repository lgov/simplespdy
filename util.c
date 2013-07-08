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

#include <stdlib.h>
#include <apr.h>
#include <apr_network_io.h>

#include "simplespdy.h"

static void log_time()
{
    apr_time_exp_t tm;

    apr_time_exp_lt(&tm, apr_time_now());
    fprintf(stderr, "%d-%02d-%02dT%02d:%02d:%02d.%06d%+03d ",
            1900 + tm.tm_year, 1 + tm.tm_mon, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_usec,
            tm.tm_gmtoff/3600);
}

void sspdy__log(int verbose_flag, const char *filename, const char *fmt, ...)
{
    va_list argp;

    if (verbose_flag) {
        log_time();

        if (filename)
            fprintf(stderr, "%s: ", filename);

        va_start(argp, fmt);
        vfprintf(stderr, fmt, argp);
        va_end(argp);
    }
}

void sspdy__log_nopref(int verbose_flag, const char *fmt, ...)
{
    va_list argp;

    if (verbose_flag) {
        va_start(argp, fmt);
        vfprintf(stderr, fmt, argp);
        va_end(argp);
    }
}

void sspdy__log_skt(int verbose_flag, const char *filename, apr_socket_t *skt,
                    const char *fmt, ...)
{
    va_list argp;

    if (verbose_flag) {
        apr_sockaddr_t *sa;
        log_time();

        if (skt) {
            /* Log local and remote ip address:port */
            fprintf(stderr, "[l:");
            if (apr_socket_addr_get(&sa, APR_LOCAL, skt) == APR_SUCCESS) {
                char buf[32];
                apr_sockaddr_ip_getbuf(buf, 32, sa);
                fprintf(stderr, "%s:%d", buf, sa->port);
            }
            fprintf(stderr, " r:");
            if (apr_socket_addr_get(&sa, APR_REMOTE, skt) == APR_SUCCESS) {
                char buf[32];
                apr_sockaddr_ip_getbuf(buf, 32, sa);
                fprintf(stderr, "%s:%d", buf, sa->port);
            }
            fprintf(stderr, "] ");
        }

        if (filename)
            fprintf(stderr, "%s: ", filename);

        va_start(argp, fmt);
        vfprintf(stderr, fmt, argp);
        va_end(argp);
    }
}
