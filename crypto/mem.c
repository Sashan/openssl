/*
 * Copyright 1995-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/e_os.h"
#include "internal/cryptlib.h"
#include "internal/mem_alloc_utils.h"
#include "internal/threads_common.h"
#include "internal/list.h"
#include "crypto/cryptlib.h"
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <openssl/crypto.h>

/*
 * the following pointers may be changed as long as 'allow_customize' is set
 */
static int allow_customize = 1;
static CRYPTO_malloc_fn malloc_impl = CRYPTO_malloc;
static CRYPTO_realloc_fn realloc_impl = CRYPTO_realloc;
static CRYPTO_free_fn free_impl = CRYPTO_free;

typedef struct crypto_mchunk {
    char *mc_bytes;
    char *mc_next;
    char *mc_last;
    OSSL_LIST_MEMBER(mc, struct crypto_mchunk);
} CRYPTO_MCHUNK;

/* 64k - mchunk structure */
#define CRYPTO_MCHUNK_DEFAULT_SZ	(65535 - sizeof(CRYPTO_MCHUNK))

DEFINE_LIST_OF(mc, CRYPTO_MCHUNK);

typedef struct crypto_mpool {
    CRYPTO_MCHUNK *mp_curr_mc;
    OSSL_LIST(mc) mp_chunks;
} CRYPTO_MPOOL;

#define CRYPTO_MPHDR_COOKIE 0xc0deface
#define CRYPTO_MPROOT_COOKIE 0xfacec0de

typedef struct crypto_mpoolhdr {
    uint32_t mph_cookie;
    uint32_t mph_len;
} CRYPTO_MPOOLHDR;

typedef struct crypto_mpoolroot {
    CRYPTO_MPOOL *mpr_mp;
    CRYPTO_MPOOLHDR mpr_mph;
} CRYPTO_MPOOLROOT;

#if !defined(OPENSSL_NO_CRYPTO_MDEBUG) && !defined(FIPS_MODULE)
#include "internal/tsan_assist.h"

#ifdef TSAN_REQUIRES_LOCKING
#define INCREMENT(x) /* empty */
#define LOAD(x) 0
#else /* TSAN_REQUIRES_LOCKING */
static TSAN_QUALIFIER int malloc_count;
static TSAN_QUALIFIER int realloc_count;
static TSAN_QUALIFIER int free_count;

#define INCREMENT(x) tsan_counter(&(x))
#define LOAD(x) tsan_load(&x)
#endif /* TSAN_REQUIRES_LOCKING */

static char md_failbuf[CRYPTO_MEM_CHECK_MAX_FS + 1];
static char *md_failstring = NULL;
static long md_count;
static int md_fail_percent = 0;
static int md_tracefd = -1;

static void parseit(void);
static int shouldfail(void);

#define FAILTEST()    \
if (shouldfail()) \
return NULL

#else

#define INCREMENT(x) /* empty */
#define FAILTEST() /* empty */
#endif

int CRYPTO_set_mem_functions(CRYPTO_malloc_fn malloc_fn,
CRYPTO_realloc_fn realloc_fn,
CRYPTO_free_fn free_fn)
{
if (!allow_customize)
    return 0;
if (malloc_fn != NULL)
    malloc_impl = malloc_fn;
if (realloc_fn != NULL)
    realloc_impl = realloc_fn;
if (free_fn != NULL)
    free_impl = free_fn;
return 1;
}

void CRYPTO_get_mem_functions(CRYPTO_malloc_fn *malloc_fn,
CRYPTO_realloc_fn *realloc_fn,
CRYPTO_free_fn *free_fn)
{
if (malloc_fn != NULL)
    *malloc_fn = malloc_impl;
if (realloc_fn != NULL)
    *realloc_fn = realloc_impl;
if (free_fn != NULL)
    *free_fn = free_impl;
}

#if !defined(OPENSSL_NO_CRYPTO_MDEBUG) && !defined(FIPS_MODULE)
void CRYPTO_get_alloc_counts(int *mcount, int *rcount, int *fcount)
{
    if (mcount != NULL)
        *mcount = LOAD(malloc_count);
    if (rcount != NULL)
        *rcount = LOAD(realloc_count);
    if (fcount != NULL)
        *fcount = LOAD(free_count);
}

/*
 * Parse a "malloc failure spec" string.  This likes like a set of fields
 * separated by semicolons.  Each field has a count and an optional failure
 * percentage.  For example:
 *          100@0;100@25;0@0
 *    or    100;100@25;0
 * This means 100 mallocs succeed, then next 100 fail 25% of the time, and
 * all remaining (count is zero) succeed.
 * The failure percentge can have 2 digits after the comma.  For example:
 *          0@0.01
 * This means 0.01% of all allocations will fail.
 */
static void parseit(void)
{
    char *semi = strchr(md_failstring, ';');
    char *atsign;

    if (semi != NULL)
        *semi++ = '\0';

    /* Get the count (atol will stop at the @ if there), and percentage */
    md_count = atol(md_failstring);
    atsign = strchr(md_failstring, '@');
    md_fail_percent = atsign == NULL ? 0 : (int)(atof(atsign + 1) * 100 + 0.5);

    if (semi != NULL)
        md_failstring = semi;
}

/*
 * Windows doesn't have random() and srandom(), but it has rand() and srand().
 * Some rand() implementations aren't good, but we're not
 * dealing with secure randomness here.
 */
#ifdef _WIN32
#define random() rand()
#define srandom(seed) srand(seed)
#endif
/*
 * See if the current malloc should fail.
 */
static int shouldfail(void)
{
    int roll = (int)(random() % 10000);
    int shoulditfail = roll < md_fail_percent;
#ifndef _WIN32
    /* suppressed on Windows as POSIX-like file descriptors are non-inheritable */
    int len;
    char buff[80];

    if (md_tracefd > 0) {
        BIO_snprintf(buff, sizeof(buff),
            "%c C%ld %%%d R%d\n",
            shoulditfail ? '-' : '+', md_count, md_fail_percent, roll);
        len = strlen(buff);
        if (write(md_tracefd, buff, len) != len)
            perror("shouldfail write failed");
    }
#endif

    if (md_count) {
        /* If we used up this one, go to the next. */
        if (--md_count == 0)
            parseit();
    }

    return shoulditfail;
}

void ossl_malloc_setup_failures(void)
{
    const char *cp = getenv("OPENSSL_MALLOC_FAILURES");
    size_t cplen = 0;

    if (cp != NULL) {
        /* if the value is too long we'll just ignore it */
        cplen = strlen(cp);
        if (cplen <= CRYPTO_MEM_CHECK_MAX_FS) {
            strncpy(md_failbuf, cp, CRYPTO_MEM_CHECK_MAX_FS);
            md_failstring = md_failbuf;
            parseit();
        }
    }
    if ((cp = getenv("OPENSSL_MALLOC_FD")) != NULL)
        md_tracefd = atoi(cp);
    if ((cp = getenv("OPENSSL_MALLOC_SEED")) != NULL)
        srandom(atoi(cp));
}
#endif

static void *ossl_malloc(size_t num, const char *file, int line)
{
    void *ptr;

    if (ossl_unlikely(num == 0))
        return NULL;
    INCREMENT(malloc_count);
    if (malloc_impl != CRYPTO_malloc) {
        ptr = malloc_impl(num, file, line);
        if (ptr != NULL || num == 0)
            return ptr;
        goto err;
    }

    if (ossl_unlikely(num == 0))
        return NULL;

    FAILTEST();
    if (allow_customize) {
        /*
         * Disallow customization after the first allocation. We only set this
         * if necessary to avoid a store to the same cache line on every
         * allocation.
         */
        allow_customize = 0;
    }

    ptr = malloc(num + sizeof(CRYPTO_MPOOLHDR));
    if (ossl_likely(ptr != NULL)) {
        CRYPTO_MPOOLHDR *mph = (CRYPTO_MPOOLHDR *)ptr;
        mph->mph_cookie = 0;
        mph->mph_len = 0;
        return ptr + sizeof(CRYPTO_MPOOLHDR);
    }

err:
    ossl_report_alloc_err(file, line);
    return NULL;
}

static void ossl_free(void *str, const char *file, int line)
{
    INCREMENT(free_count);
    if (free_impl != CRYPTO_free) {
        free_impl(str, file, line);
        return;
    }

    free(str);
}

static void *ossl_mpool_create_mc(size_t chunk_sz, const char *file, int line)
{
    CRYPTO_MCHUNK *mc;

    mc = ossl_malloc(chunk_sz, file, line);
    if (mc != NULL) {
        mc->mc_bytes = (char *)mc + sizeof(CRYPTO_MCHUNK);
        mc->mc_next = mc->mc_bytes;
        mc->mc_last = (char *)mc + chunk_sz;
        ossl_list_mc_init_elem(mc);
    }

    return mc;
}

static int ossl_mpool_chksize(CRYPTO_MCHUNK *mc, size_t want)
{
    return (mc->mc_next + want) < mc->mc_last;
}

static void *ossl_mpool_alloc(CRYPTO_MPOOL *mp, size_t num, const char *file, int line)
{
    CRYPTO_MCHUNK *curr_mc;
    CRYPTO_MPOOLHDR *mph = NULL;
    CRYPTO_MPOOLROOT *mpr = NULL;
    void *rv;

    curr_mc = mp->mp_curr_mc;
    /*
     * no chunk or want too much memory, then create new chunk
     * and allocate bytes from there. This may waste too much
     * memory. Better alternative is to walk existing chunks
     * and try to find  chunk with enough space to satisfy
     * allocation.
     */
    if (curr_mc == NULL || !ossl_mpool_chksize(curr_mc, num + sizeof(CRYPTO_MPOOLHDR))) {
        /* need to allocate extra bytes for root header */
        num += sizeof(CRYPTO_MPOOLROOT);
        /*
         * if allocation does not fit default chunk size, the extra allocation must also allocate
         * chunk metadata too.
         */
        num = (num < CRYPTO_MCHUNK_DEFAULT_SZ) ? CRYPTO_MCHUNK_DEFAULT_SZ : num + sizeof(CRYPTO_MCHUNK);
        curr_mc = ossl_mpool_create_mc(CRYPTO_MCHUNK_DEFAULT_SZ, file, line);
        if (curr_mc != NULL) {
            ossl_list_mc_insert_tail(&mp->mp_chunks, curr_mc);
            mp->mp_curr_mc = curr_mc;
            mpr = (CRYPTO_MPOOLROOT *)curr_mc->mc_next;
            curr_mc->mc_next += num;
        }
    } else {
        /* need to allocate extra bytes for pool buf header */
        num += sizeof(CRYPTO_MPOOLHDR);
        mph = (CRYPTO_MPOOLHDR *)curr_mc->mc_next;
        curr_mc->mc_next += num;
    }

    if (mpr != NULL) {
        mpr->mpr_mp = mp;
        mpr->mpr_mph.mph_cookie = CRYPTO_MPROOT_COOKIE;
        mpr->mpr_mph.mph_len = num; /* including header */
        rv = &mpr[1]; /* return next bytes which follow header */
    } else if (mph != NULL) {
        mph->mph_cookie = CRYPTO_MPHDR_COOKIE;
        mph->mph_len = num; /* including header */
        rv = &mph[1]; /* return next bytes which follow header */
    } else {
        rv = NULL;
    }

    return rv;
}

/*
 * no realloc provided by pool, fallback to libc malloc
 */
static void *ossl_mpool_realloc(void *str, size_t num, const char *file, int line)
{
    CRYPTO_MPOOLHDR *mph = (CRYPTO_MPOOLHDR *)str;
    CRYPTO_MPOOLROOT *mpr = (CRYPTO_MPOOLROOT *)str;
    char *new_buf;

    mph--;
    if (mph->mph_cookie == CRYPTO_MPHDR_COOKIE) {
        new_buf = ossl_malloc(num + mph->mph_len, file, line);
        if (new_buf == NULL)
            return NULL;

        memcpy(new_buf, mph, mph->mph_len);
        /*
         * mph will be freed with pool. Reallocated buffer is no longer
         * part of memory pool.
         */
        mph = (CRYPTO_MPOOLHDR *)new_buf;
        mph->mph_cookie = 0;
        mph->mph_len = 0;
    } else {
        /*
         * This is bad we can not reallocate root buffer. Trying to
         * reallocate root buffer will cause a memory leak of whole
         * pool. The only solution is to drop CRYPTO_MPOOLHDR and
         * always use CRYPTO_MPOOLROOT instead where we keep pointer
         * to memory pool.
         *
         * just fail the allocation.
         */
        OPENSSL_assert(mpr != NULL);
        return NULL;
    }

    return new_buf;
}

static void ossl_mpool_destroy(CRYPTO_MPOOL *mp)
{
    CRYPTO_MCHUNK *mc;

    while ((mc = ossl_list_mc_head(&mp->mp_chunks)) != NULL) {
        ossl_list_mc_remove(&mp->mp_chunks, mc);
        ossl_free(mc, __FILE__, __LINE__);
    }

    ossl_free(mp, __FILE__, __LINE__);
}

void *CRYPTO_malloc(size_t num, const char *file, int line)
{
    CRYPTO_MPOOL *mp;

    mp = CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_MPOOL, CRYPTO_THREAD_NO_CONTEXT);
    if (mp != NULL) {
        return ossl_mpool_alloc(mp, num, file, line);
    }

    return ossl_malloc(num, file, line);

}

void *CRYPTO_zalloc(size_t num, const char *file, int line)
{
    void *ret;

    ret = CRYPTO_malloc(num, file, line);
    if (ret != NULL)
        memset(ret, 0, num);

    return ret;
}

void *CRYPTO_aligned_alloc(size_t num, size_t alignment, void **freeptr,
    const char *file, int line)
{
    *freeptr = NULL;

    /* Ensure that alignment is a power of two no larger than 65536 */
    if (alignment == 0 || (alignment & (alignment - 1)) != 0
        || alignment > 65536) {
        ossl_report_alloc_err_inv(file, line);
        return NULL;
    }

    /* Allow non-malloc() allocations as long as no malloc_impl is provided. */
    if (malloc_impl == CRYPTO_malloc) {
#if defined(_BSD_SOURCE) || (defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L)
        void *ret;

        /* posix_memalign() requires alignment to be at least sizeof(void *) */
        if (alignment < sizeof(void *))
            alignment = sizeof(void *);

        if (posix_memalign(&ret, alignment, num) == 0) {
            *freeptr = ret;
            return ret;
        }
#endif
    }

    return ossl_malloc_align(num, alignment, freeptr, file, line);
}

void *CRYPTO_realloc(void *str, size_t num, const char *file, int line)
{
    void *ret;
    CRYPTO_MPOOLHDR *mph;

    /*
     * if memory to be reallocated comes from memory pool then do the
     * reallocation pool-way.
     */
    mph = (CRYPTO_MPOOLHDR *)str;
    if (mph != NULL) {
        mph--;
        if (mph->mph_cookie == CRYPTO_MPHDR_COOKIE || mph->mph_cookie == CRYPTO_MPHDR_COOKIE)
            return ossl_mpool_realloc(str, num, file, line);
    }

    INCREMENT(realloc_count);
    if (realloc_impl != CRYPTO_realloc) {
        ret = realloc_impl(str, num, file, line);

        if (num == 0 || ret != NULL)
            return ret;

        goto err;
    }

    if (str == NULL)
        return CRYPTO_malloc(num, file, line);

    if (num == 0) {
        CRYPTO_free(str, file, line);
        return NULL;
    }

    FAILTEST();

    ret = realloc(str, num);

err:
    if (num != 0 && ret == NULL)
        ossl_report_alloc_err(file, line);

    return ret;
}

void *CRYPTO_clear_realloc(void *str, size_t old_len, size_t num,
    const char *file, int line)
{
    void *ret = NULL;

    if (str == NULL)
        return CRYPTO_malloc(num, file, line);

    if (num == 0) {
        CRYPTO_clear_free(str, old_len, file, line);
        return NULL;
    }

    /* Can't shrink the buffer since memcpy below copies |old_len| bytes. */
    if (num < old_len) {
        OPENSSL_cleanse((char *)str + num, old_len - num);
        return str;
    }

    ret = CRYPTO_malloc(num, file, line);
    if (ret != NULL) {
        memcpy(ret, str, old_len);
        CRYPTO_clear_free(str, old_len, file, line);
    }
    return ret;
}

void CRYPTO_free(void *str, const char *file, int line)
{
    CRYPTO_MPOOLHDR *mph;
    CRYPTO_MPOOLROOT *mpr;

    if (str != NULL) {
        /*
         * Is safe if all allocations are done with CRYPTO_malloc(),
         * where mpool header is preprended to every allocation.
         */
        mph = (CRYPTO_MPOOLHDR *)str;
	mph--;
        switch (mph->mph_cookie) {
        case CRYPTO_MPROOT_COOKIE:
            mph--;
            mpr = (CRYPTO_MPOOLROOT *)mph;
            ossl_mpool_destroy(mpr->mpr_mp);
            /* FALLTHRU */
        case CRYPTO_MPHDR_COOKIE:
            return; /* no-op, pool must be dropped at root */
        default:
            str = mph; /* discard pool header */
        }
    }

    ossl_free(str, file, line);
}

void CRYPTO_clear_free(void *str, size_t num, const char *file, int line)
{
    if (str == NULL)
        return;
    if (num)
        OPENSSL_cleanse(str, num);
    CRYPTO_free(str, file, line);
}

#if !defined(OPENSSL_NO_CRYPTO_MDEBUG)

#ifndef OPENSSL_NO_DEPRECATED_3_0
int CRYPTO_mem_ctrl(int mode)
{
    (void)mode;
    return -1;
}

int CRYPTO_set_mem_debug(int flag)
{
    (void)flag;
    return -1;
}

int CRYPTO_mem_debug_push(const char *info, const char *file, int line)
{
    (void)info;
    (void)file;
    (void)line;
    return 0;
}

int CRYPTO_mem_debug_pop(void)
{
    return 0;
}

void CRYPTO_mem_debug_malloc(void *addr, size_t num, int flag,
    const char *file, int line)
{
    (void)addr;
    (void)num;
    (void)flag;
    (void)file;
    (void)line;
}

void CRYPTO_mem_debug_realloc(void *addr1, void *addr2, size_t num, int flag,
    const char *file, int line)
{
    (void)addr1;
    (void)addr2;
    (void)num;
    (void)flag;
    (void)file;
    (void)line;
}

void CRYPTO_mem_debug_free(void *addr, int flag,
    const char *file, int line)
{
    (void)addr;
    (void)flag;
    (void)file;
    (void)line;
}

int CRYPTO_mem_leaks(BIO *b)
{
    (void)b;
    return -1;
}

#ifndef OPENSSL_NO_STDIO
int CRYPTO_mem_leaks_fp(FILE *fp)
{
    (void)fp;
    return -1;
}
#endif

int CRYPTO_mem_leaks_cb(int (*cb)(const char *str, size_t len, void *u),
    void *u)
{
    (void)cb;
    (void)u;
    return -1;
}

#endif

void CRYPTO_mpool_start(void)
{
    CRYPTO_MPOOL *mp;
    CRYPTO_MPOOL *old_mp;

    old_mp = CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_MPOOL, CRYPTO_THREAD_NO_CONTEXT);
    if (old_mp != NULL && ossl_list_mc_num(&old_mp->mp_chunks) == 0) {{
        /*
         * No memory was allocated from existing pool, just use it.
         */
        return;
    }

    mp = ossl_malloc(sizeof(CRYPTO_MPOOL), __FILE__, __LINE__);
    mp->mp_curr_mc = NULL;
    mp->mp_allocs = 0;
    ossl_list_mc_init(&mp->mp_chunks);
    /*
     * just overwrite existing pool (old_mp) with new pool. The pool is destroyed
     * when application releases the 'root' object from pool.
     */
    CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_MPOOL, CRYPTO_THREAD_NO_CONTEXT, mp);
}

void CRYPTO_mpool_stop(void)
{
    /*
     * Remember pool is rleased with its 'root' object. Here we just tell library
     * to stop allocating from pool.
     */
    CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_MPOOL, CRYPTO_THREAD_NO_CONTEXT, NULL);
}

#endif
