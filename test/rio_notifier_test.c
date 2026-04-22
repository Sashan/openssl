/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/rio_notifier.h"
#include "testutil.h"

int ossl_rio_notifier_wsa_test_get_started(void);
int ossl_rio_notifier_wsa_test_get_startup_count(void);

static int test_rio_notifier_smoke(void)
{
    RIO_NOTIFIER nfy = { -1, -1 };
    int ret = 0;

    if (!TEST_true(ossl_rio_notifier_init(&nfy)))
        goto err;

    if (!TEST_int_ne(ossl_rio_notifier_as_fd(&nfy), (int)INVALID_SOCKET)
        || !TEST_true(ossl_rio_notifier_signal(&nfy))
        || !TEST_true(ossl_rio_notifier_unsignal(&nfy)))
        goto err;

    ret = 1;

err:
    ossl_rio_notifier_cleanup(&nfy);
    return ret;
}

/*
 * The old Windows WSA lifecycle dropped process-wide WSA state when the last
 * notifier was cleaned up. A concurrent notifier startup could race with that
 * cleanup. The fixed lifecycle keeps RIO WSA startup alive for the process, so
 * cleanup must not reset WSA state or make a later notifier run WSAStartup()
 * again.
 */
static int test_wsa_startup_process_lifetime(void)
{
    RIO_NOTIFIER nfy = { -1, -1 };
    int ret = 0;
    int was_started = ossl_rio_notifier_wsa_test_get_started();
    int startup_count = ossl_rio_notifier_wsa_test_get_startup_count();
    int expected_count = startup_count + (was_started ? 0 : 1);

    if (!TEST_true(ossl_rio_notifier_init(&nfy))
        || !TEST_int_eq(ossl_rio_notifier_wsa_test_get_started(), 1)
        || !TEST_int_eq(ossl_rio_notifier_wsa_test_get_startup_count(),
            expected_count))
        goto err;

    ossl_rio_notifier_cleanup(&nfy);
    if (!TEST_int_eq(ossl_rio_notifier_wsa_test_get_started(), 1)
        || !TEST_int_eq(ossl_rio_notifier_wsa_test_get_startup_count(),
            expected_count))
        goto err;

    if (!TEST_true(ossl_rio_notifier_init(&nfy))
        || !TEST_int_eq(ossl_rio_notifier_wsa_test_get_started(), 1)
        || !TEST_int_eq(ossl_rio_notifier_wsa_test_get_startup_count(),
            expected_count))
        goto err;

    ret = 1;

err:
    ossl_rio_notifier_cleanup(&nfy);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_rio_notifier_smoke);
    ADD_TEST(test_wsa_startup_process_lifetime);
    return 1;
}
