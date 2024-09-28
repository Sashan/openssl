/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <ssl/ssl_local.h>

#include "testutil.h"
#include "testutil/output.h"

#ifndef B_TRUE
# define B_TRUE (1 == 1)
#endif

#ifndef B_FALSE
# define B_FALSE (1 != 1)
#endif

struct {
    time_t time;
    time_t timeout;
    time_t expected;
    time_t expected_ovf;
} test_sample[] = {
    {
        0xffffffffffffffff,
        0x0,
        0xffffffffffffffff,
        B_FALSE
    },
    {
        0x0,
        0xffffffffffffffff,
        0x0,
        B_FALSE 
    },
    {
        0xffffffffffffffff,
        0x100,
        0xff,
        B_FALSE 
    },
    {
        0x100,
        0xffffffffffffffff,
        0x100,
        B_FALSE
    },
    {
        0x7fffffffffffffff,
        0x7fffffffffffffff,
        0xfffffffffffffffe,
        B_TRUE
    },
    {
        0x20,
        0x7fffffffffffffff,
        0x800000000000001f,
        B_TRUE
    },
    {
        0x7fffffffffffffff,
        0x20,
        0x800000000000001f,
        B_TRUE
    },
    {
        0x130,
        0x66f3cafa,
        0x66f3cc2a,
        B_FALSE
    },
    {
        0x66f3cafa,
        0x130,
        0x66f3cc2a,
        B_FALSE
    },
    {
        0x66f3caf8,
        0x130,
        0x66f3cc28,
        B_FALSE
    },
    {
        0x130,
        0x66f3caf8,
        0x66f3cc28,
        B_FALSE
    },
    {
        0x2020202020202020,
        0xffffffffffffffff,
        0x2020202020202020,
        B_FALSE
    },
    {
        0xffffffffffffffff,
        0x2020202020202020,
        0x202020202020201f,
        B_FALSE
    },
    { 0 }
};

int test_ssl_timeout(void)
{
    int i = 0;
    SSL_SESSION *s;
    SSL_CTX *ctx;
    OSSL_LIB_CTX *libctx;
    time_t result;
    int overflow;
    int testresult = 1;

    libctx = OSSL_LIB_CTX_new();
    if (!TEST_ptr(libctx))
        return 0;

    ctx = SSL_CTX_new_ex(libctx, NULL, TLS_method());
    if (!TEST_ptr(ctx)) {
        OSSL_LIB_CTX_free(libctx);
        return 0;
    }

    s = SSL_SESSION_new();
    if (!TEST_ptr(ctx)) {
        SSL_CTX_free(ctx);
        OSSL_LIB_CTX_free(libctx);
        return 0;
    }

    while (!((test_sample[i].time == 0) && (test_sample[i].timeout == 0))) {
        ssl_session_set_times(s, test_sample[i].time, test_sample[i].timeout);
        ssl_session_calculate_timeout(s);
        ssl_session_get_calc_timeout(s, &result, &overflow);
        if (!TEST_int_eq(result, test_sample[i].expected)) {
            testresult = 0;
            break;
        }
        if (!TEST_int_eq(overflow, test_sample[i].expected_ovf)) {
            testresult = 0;
            break;
        }

        i++;
    }

    SSL_SESSION_free(s);
    SSL_CTX_free(ctx);
    OSSL_LIB_CTX_free(libctx);

    return testresult;
}


int setup_tests(void)
{
    ADD_TEST(test_ssl_timeout);

    return 1;
}
