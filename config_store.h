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

#ifndef CONFIG_STORE_H
#define CONFIG_STORE_H

typedef struct sspdy_config_store_t sspdy_config_store_t;

typedef struct sspdy_general_config_store_t {

} sspdy_general_config_store_t;

struct sspdy_config_store_t {
    sspdy_general_config_store_t *general_config_store;
};

apr_status_t
create_general_config_store(sspdy_general_config_store_t **config_store,
                            apr_pool_t *pool);

apr_status_t
create_config_store(sspdy_config_store_t **config_store,
                    sspdy_general_config_store_t *general_config_store,
                    apr_pool_t *pool);

apr_status_t store_config_for_connection(apr_pool_t *pool);



#endif
