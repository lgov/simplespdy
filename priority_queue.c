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

#include "priority_queue.h"
#include <math.h>
#include <stdio.h>
#define NR_OF_ELEMENTS 10

typedef struct heap_element_t {
    void *element;
    int priority;
} heap_element_t;

struct sspdy_priority_queue_t {
    apr_pool_t *pool;
    heap_element_t *elements;
    int nelts;
};

sspdy_priority_queue_t *sspdy_create_priority_queue(apr_pool_t *pool)
{
    sspdy_priority_queue_t *pqueue;

    pqueue = apr_palloc(pool, sizeof(sspdy_priority_queue_t));
    pqueue->pool = pool;
    pqueue->elements = apr_pcalloc(pool, NR_OF_ELEMENTS * sizeof(heap_element_t));
    pqueue->nelts = 0;
    return pqueue;
}

/* TODO: maintain order of insertion for same priority */
void sspdy_priority_queue_insert(sspdy_priority_queue_t *pqueue, void *element, int priority)
{
    heap_element_t *h_el;

    if (pqueue->nelts + 1 > NR_OF_ELEMENTS) {
        /* reallocate */
    }

    pqueue->nelts++;

    h_el = &pqueue->elements[pqueue->nelts];
    h_el->priority = priority;
    h_el->element = element;

    while (1) {
        int parent;
        heap_element_t *p_el;

        parent = pqueue->nelts / 2;

        if (parent == 0)
            break;

        p_el = &pqueue->elements[parent];

        if (p_el->priority > h_el->priority) {
            /* swap elements */
            heap_element_t swap;

            memcpy(&swap, p_el, sizeof(heap_element_t));
            memcpy(p_el, h_el, sizeof(heap_element_t));
            memcpy(h_el, &swap, sizeof(heap_element_t));
        } else {
            break;
        }
    }
}

const void *sspdy_priority_queue_remove_top(sspdy_priority_queue_t *pqueue)
{
    heap_element_t *res_el = &pqueue->elements[1];
    void *element = res_el->element;
    int cur;

    /* move the last leaf to the top */
    memcpy(&pqueue->elements[1], &pqueue->elements[pqueue->nelts],
           sizeof(heap_element_t));
    pqueue->nelts--;

    /* keep swapping this element until the heap is reordered */
    cur = 1;
    while (1) {
        heap_element_t *chl_el, *chr_el, *cmax_el, *cur_el;

        if (cur * 2 + 1 > pqueue->nelts)
            break;

        cur_el = &pqueue->elements[cur];
        chl_el = &pqueue->elements[cur * 2];
        chr_el = &pqueue->elements[cur * 2 + 1];

        if (chl_el->priority < chr_el->priority) {
            cmax_el = chl_el;
            cur = cur * 2;
        } else {
            cmax_el = chr_el;
            cur = cur * 2 + 1;
        }

        if (cmax_el->priority < cur_el->priority) {
            heap_element_t swap;

            memcpy(&swap, cur_el, sizeof(heap_element_t));
            memcpy(cur_el, cmax_el, sizeof(heap_element_t));
            memcpy(cmax_el, &swap, sizeof(heap_element_t));
        } else {
            break;
        }
    }
    return element;
}

void log_heap(sspdy_priority_queue_t *pqueue)
{
    int level = 1;
    int el = 1;

    printf("\n");

    while (1) {
        int i;

        for (i = 0; i < pow(2, level - 1); i++) {
            heap_element_t *h_el;

            h_el = &pqueue->elements[el++];

            printf(" %s ", (const char *)h_el->element);

            if (el > pqueue->nelts)
                break;
        }

        if (el > pqueue->nelts)
            break;

        level++;
        printf("\n");
    }
    printf("\n");
}
