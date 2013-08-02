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
#include "priority_queue.h"

#define CTEST_MAIN
#include "ctest.h"

CTEST_DATA(heap) {
    apr_pool_t *test_pool;
};

/* CTest note: the ap_log_data struct is available in setup/teardown/run
 functions as 'data'. */
CTEST_SETUP(heap)
{
    /* Initialize the Apache portable runtime library. */
    apr_initialize();
    atexit(apr_terminate);

    apr_pool_create(&data->test_pool, NULL);
}

CTEST_TEARDOWN(heap)
{
    apr_pool_destroy(data->test_pool);
}

#if 0
CTEST2(heap, test1)
{
    const char *str1 = "string";
    const char *str;

    sspdy_heap_t *heap = sspdy_create_heap(data->test_pool);
    sspdy_heap_insert(heap, str1, 1);

    str = (const char *)sspdy_heap_remove_top(heap);
    ASSERT_STR(str1, str);
}


CTEST2(heap, test2)
{
    const char *str1 = "string1";
    const char *str2 = "string2";
    const char *str;

    /* add in order */
    sspdy_heap_t *heap = sspdy_create_heap(data->test_pool);
    sspdy_heap_insert(heap, str1, 1);
    sspdy_heap_insert(heap, str2, 2);

    str = (const char *)sspdy_heap_remove_top(heap);
    ASSERT_STR(str1, str);
    str = (const char *)sspdy_heap_remove_top(heap);
    ASSERT_STR(str2, str);
}

CTEST2(heap, test3)
{
    const char *str1 = "string1";
    const char *str2 = "string2";
    const char *str;

    /* add in reverse order */
    sspdy_heap_t *heap = sspdy_create_heap(data->test_pool);
    sspdy_heap_insert(heap, str2, 2);
    sspdy_heap_insert(heap, str1, 1);

    str = (const char *)sspdy_heap_remove_top(heap);
    ASSERT_STR(str1, str);
    str = (const char *)sspdy_heap_remove_top(heap);
    ASSERT_STR(str2, str);
}
#endif

CTEST2(heap, test4)
{
    const char *str1 = "string1";
    const char *str2 = "string2";
    const char *str3 = "string3";
    const char *str4 = "string4";
    const char *str5 = "string5";
    const char *str6 = "string6";
    const char *str7 = "string7";
    const char *str8 = "string8";
    const char *str;

    /* add in random order */
    sspdy_heap_t *heap = sspdy_create_heap(data->test_pool);
    sspdy_heap_insert(heap, str4, 4);
    sspdy_heap_insert(heap, str1, 1);
    sspdy_heap_insert(heap, str3, 3);
    sspdy_heap_insert(heap, str2, 2);

    log_heap(heap);
    str = (const char *)sspdy_heap_remove_top(heap);
    ASSERT_STR(str1, str);
    log_heap(heap);
    str = (const char *)sspdy_heap_remove_top(heap);
    ASSERT_STR(str2, str);
    log_heap(heap);
    str = (const char *)sspdy_heap_remove_top(heap);
    ASSERT_STR(str3, str);
    log_heap(heap);
    str = (const char *)sspdy_heap_remove_top(heap);
    ASSERT_STR(str4, str);
    log_heap(heap);
}

int main(int argc, const char *argv[])
{
    return ctest_main(argc, argv);
}
