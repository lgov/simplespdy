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

#ifndef PRIORITY_QUEUE_H
#define PRIORITY_QUEUE_H

#include <apr.h>
#include <apr_pools.h>

typedef struct sspdy_heap_t sspdy_heap_t;

sspdy_heap_t *sspdy_create_heap(apr_pool_t *pool);

/* lower = higher priority */
void sspdy_heap_insert(sspdy_heap_t *heap, void *element, int priority);

const void * sspdy_heap_remove_top(sspdy_heap_t *heap);

void log_heap(sspdy_heap_t *heap);

#endif
