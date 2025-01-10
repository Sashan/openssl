/*
 *  Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License").  You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/quic.h>

#define BUF_SIZE 4096
#define FILE_MAX_SZ (8 * BUF_SIZE)

/*
 * We use QUIC client and QUIC server to test SSL_new_from_listener(3)
 * API call. The main() function uses fork(2) syscall to create a client
 * process. The main() then continues to run as a server. The main()
 * expects those command line arguments:
 *    port
 *    path to server certificate
 *    path to server key
 *
 * Both client and server use QUIC API in multistream mode with blocking
 * calls to libssl.
 *
 * Yo test SSL_new_from_listener() works as expected we need to implement
 * application which transfers files in active-FTP like fashion.
 * Once client connects to server it opens a stream (ssl_qstream_cmd) to
 * transfer request (command) to fetch desired file. The request looks as
 * follows:
 *    /localhost:4445/file_1024.txt
 * The request above has two path components:
 *    - host component (localhost:4445)
 *    - filename component (file_1024.txt)
 * This tells server to connect back to localhost:4445 and transfer
 * desired file to client. Client concludes ssl_stream_cmd as soon as
 * request is written.
 *
 * The unit test here also implements http-like mode. In http-like mode
 * client sends request with filename component only. Such request
 * looks as follows:
 *    - /file_1024.txt
 * In http-like mode client writes request to stream and then reads
 * the server's response from the same stream.
 *
 * When testing is done client sends request 'QUIT' to terminate
 * server's loop and exit.
 *
 * Rather than sending real files the server generates content on
 * the fly. For example 'some_file_2048.txt' tells server to send
 * back a payload of 2048 bytes.
 */

/*
 * hq-interop application protocol
 */
static const unsigned char alpn_ossltest[] = {
    10, 'h', 'q', '-', 'i', 'n', 't', 'e', 'r', 'o', 'p',
};
static const char *whoami = "Server";
static int quit;

#ifndef __func__
# define __func__ ""
#endif

static int select_alpn(SSL *ssl, const unsigned char **out,
                       unsigned char *out_len, const unsigned char *in,
                       unsigned int in_len, void *arg)
{
    if (SSL_select_next_proto((unsigned char **)out, out_len, alpn_ossltest,
                              sizeof(alpn_ossltest), in,
                              in_len) == OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

static SSL_CTX *create_ctx(const char *cert_path, const char *key_path)
{
    SSL_CTX *ssl_ctx;
    int chk;

    /*
     * If cert and keys are missing we assume a QUIC client,
     * otherwise we try to create a context for QUIC server.
     */
    if (cert_path == NULL && key_path == NULL) {
        ssl_ctx = SSL_CTX_new(OSSL_QUIC_client_method());
        if (ssl_ctx == NULL) {
            fprintf(stderr, "[ %s ] %s SSL_CTX_new %s\n", whoami, __func__,
                    ERR_reason_error_string(ERR_get_error()));
            goto err;
        }

    } else {
        ssl_ctx = SSL_CTX_new(OSSL_QUIC_server_method());
        if (ssl_ctx == NULL) {
            fprintf(stderr, "[ %s ] %s SSL_CTX_new %s\n", whoami, __func__,
                    ERR_reason_error_string(ERR_get_error()));
            goto err;
        }
        SSL_CTX_set_alpn_select_cb(ssl_ctx, select_alpn, NULL);
    }

    if (cert_path != NULL) {
        chk = SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_path);
        if (chk == 0) {
            fprintf(stderr, "[ %s ] %s SSL_CTX_use_certificate_chain_file(%s) %s\n",
                    whoami, __func__, cert_path,
                    ERR_reason_error_string(ERR_get_error()));
            goto err;
        }
    }

    if (key_path != NULL) {
        chk = SSL_CTX_use_PrivateKey_file(ssl_ctx, key_path, SSL_FILETYPE_PEM);
        if (chk == 0) {
            fprintf(stderr, "[ %s ] %s SSL_CTX_use_PrivateKey(%s)  %s\n",
                    whoami, __func__, key_path,
                    ERR_reason_error_string(ERR_get_error()));
            goto err;
        }
    }

    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);

    return ssl_ctx;

err:
    SSL_CTX_free(ssl_ctx);
    return NULL;
}

static BIO *create_socket(uint16_t port, struct in_addr *ina)
{
    int fd = -1;
    struct sockaddr_in sa;
    BIO *bio_sock = NULL;
    int chk;

    fd = BIO_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0);
    if (fd < 0) {
        fprintf(stderr, "[ %s ] %s cannot BIO_socket %s", whoami, __func__,
                ERR_reason_error_string(ERR_get_error()));
        goto err;
    }

    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr = *ina;
    chk = bind(fd, (const struct sockaddr *)&sa, sizeof(sa));
    if (chk != 0) {
        fprintf(stderr, "[ %s ] %s bind(%d) %s\n", whoami, __func__, port,
                strerror(errno));
        goto err;
    }

    bio_sock = BIO_new(BIO_s_datagram());
    if (bio_sock == NULL) {
        fprintf(stderr, "[ %s ] %s BIO_new %s\n", whoami, __func__,
                ERR_reason_error_string(ERR_get_error()));
        goto err;
    }

    chk = BIO_set_fd(bio_sock, fd, BIO_CLOSE);
    if (chk == 0) {
        fprintf(stderr, "[ %s ] %s BIO_set_fd %s\n", whoami, __func__,
                ERR_reason_error_string(ERR_get_error()));
        goto err;
    }

    return bio_sock;

err:
    BIO_free(bio_sock);
    BIO_closesocket(fd);
    return NULL;
}

/*
 * We use mem BIO to generate a payload for client.
 * we expect filename to be in format like abc_1234.txt
 */
static BIO *open_fake_file(const char *filename)
{
    size_t fsize, i;
    char *tmp_buf = strdup(filename);
    char *p;
    char *fsize_str;
    BIO *bio_fakef = NULL;
    int chk;

    if (tmp_buf == NULL)
        goto done;

    fsize_str = strchr(tmp_buf, '_');
    if (fsize_str == NULL)
        goto done;
    fsize_str++;

    p = strchr(fsize_str, '.');
    if (p == NULL)
        goto done;
    *p = '\0';

    fsize = atoi(fsize_str);
    if (fsize > FILE_MAX_SZ || fsize <= 0)
        goto done;

    free(tmp_buf);
    tmp_buf = (char *)OPENSSL_malloc(fsize);
    if (tmp_buf == NULL)
        goto done;

    bio_fakef = BIO_new_mem_buf(tmp_buf, fsize);
    if (bio_fakef == NULL)
        goto done;

    chk = BIO_set_close(bio_fakef, BIO_CLOSE);
    if (chk == 0) {
        BIO_free(bio_fakef);
        bio_fakef = NULL;
        goto done;
    }

    /*
     * fill buffer with 'OpenSSLOpenSSLOpenS...' pattern
     */
    for (i = 0; i < fsize; i++)
        tmp_buf[i] = "OpenSSL"[i % (sizeof ("OpenSSL") - 1)];

    tmp_buf = NULL;

done:
    OPENSSL_free(tmp_buf);

    return bio_fakef;
}

static void close_fake_file(BIO *bio_fakef)
{
    char *tmp_buf;

    (void) BIO_reset(bio_fakef);
    (void) BIO_get_mem_data(bio_fakef, &tmp_buf);
    BIO_free(bio_fakef);
    OPENSSL_free(tmp_buf);
}

/*
 * writes pauload specified by filename to ssl_qstream
 */
static void send_file(SSL *ssl_qstream, const char *filename)
{
    unsigned char buf[BUF_SIZE];
    BIO *bio_fakef;
    size_t bytes_read = 0;
    size_t bytes_written = 0;
    size_t offset = 0;
    int chk;

    fprintf(stdout, "( Server ) Serving %s\n", filename);
    bio_fakef = open_fake_file(filename);
    if (bio_fakef == NULL) {
        fprintf(stderr, "[ Server ] Unable to open %s\n", filename);
        ERR_print_errors_fp(stderr);
        goto done;
    }

    while (BIO_eof(bio_fakef) <= 0) {
        bytes_read = 0;
        chk = BIO_read_ex(bio_fakef, buf, BUF_SIZE, &bytes_read);
        if (chk == 0) {
            chk = BIO_eof(bio_fakef);
            if (chk == 0) {
                fprintf(stderr, "[ Server ] Failed to read from %s\n", filename);
                ERR_print_errors_fp(stderr);
                goto done;
            } else {
                break;
            }
        }

        offset = 0;
        for (;;) {
            bytes_written = 0;
            chk = SSL_write_ex(ssl_qstream, &buf[offset], bytes_read, &bytes_written);
            if (chk == 0) {
                chk = SSL_get_error(ssl_qstream, chk);
                switch (chk) {
                case SSL_ERROR_WANT_WRITE:
                    fprintf(stderr, "[ Server ] %s Send buffer full, retrying\n",
                            __func__);
                    continue;
                default:
                    fprintf(stderr, "[ Server ] %s Unhandled error cause %s\n",
                            __func__, ERR_reason_error_string(chk));
                    goto done;
                }
            }
            bytes_read -= bytes_written;
            offset += bytes_written;
            bytes_written = 0;
            if (bytes_read == 0)
                break;
        }
    }

done:
    close_fake_file(bio_fakef);

    return;
}

/*
 * reads request from ssl_qstream. Two things may happen here depending on
 * request type:
 *    - if we deal with http-like request (GET /file_123.txt) function
 *      writes response directly to ssl_qstream
 *
 *    - if we deal with active-FTP-like mode (GET /localhost:xxxx/file_123.txt)
 *      function closes ssl_qstream and uses ssl_qlistener to create a new
 *      QUIC connection object (ssl_qconn). Function uses ssl_qconn to
 *      connect back to client and open stream to send response.
 * In both cases function always frees ssl_qstream passed by caller.
 */
static void process_new_stream(SSL *ssl_qlistener, SSL *ssl_qstream)
{
    unsigned char buf[BUF_SIZE];
    char path[BUF_SIZE];
    char *req = (char *)buf;
    char *reqname;
    char *dst_host;
    char *dst_port_str;
    size_t nread;
    char *creturn;
    BIO_ADDRINFO *bai = NULL;
    SSL *ssl_qconn = NULL;
    int chk;

    memset(buf, 0, BUF_SIZE);
    chk = SSL_read_ex(ssl_qstream, buf, sizeof(buf) - 1, &nread);
    if (chk == 0) {
        quit = 1;
        SSL_free(ssl_qstream);
        return;
    }

    fprintf(stdout, "(Server) Request is %s\n", req);

    /*
     * This is a shortcut to handle QUIT command sent by client.
     * Yhe QUIT command is the only request which comes without
     * a '/'. We assume anything what does not contain '/' is
     * a QUIT command.
     */
    reqname = strrchr(req, '/');
    if (reqname == NULL) {
        quit = 1;
        SSL_free(ssl_qstream);
        return;
    }
    *reqname = '\0';
    reqname++;
    creturn = strchr(reqname, '\r');
    if (creturn != NULL)
        *creturn = '\0';

    snprintf(path, BUF_SIZE, "%s", reqname);

    /*
     * in case request is something like:
     *    /hostname:port/file.txt
     * the server connects back to client to
     * transfer file.txt (think of active FTP),
     */
    dst_host = strrchr(req, '/');
    if (dst_host != NULL) {

        dst_host++;
        dst_port_str = strchr(dst_host, ':');
        if (dst_port_str == NULL) {
            dst_host = NULL;
        } else {
            *dst_port_str = '\0';
            dst_port_str++;
            chk = BIO_lookup_ex(dst_host, dst_port_str, BIO_LOOKUP_CLIENT,
                                AF_INET, SOCK_DGRAM, 0, &bai);
            if (chk == 0) {
                fprintf(stderr, "[ Server ] %s BIO_lookup_ex(%s, %s) error (%s)\n",
                        __func__, dst_host, dst_port_str, strerror(errno));
                quit = 1;
                goto done;
            }

            ssl_qconn = SSL_new_from_listener(ssl_qlistener, 0);
            if (ssl_qconn == NULL) {
                fprintf(stderr, "[ Server ] %s SSL_new_from_listener error (%s)\n",
                        __func__, ERR_reason_error_string(ERR_get_error()));
                quit = 1;
                goto done;
            }

            chk = SSL_set1_initial_peer_addr(ssl_qconn,
                                             BIO_ADDRINFO_address(bai));
            if (chk == 0) {
                fprintf(stderr, "[ Server ] %s SSL_new_from_listener error (%s)\n",
                        __func__, ERR_reason_error_string(ERR_get_error()));
                quit = 1;
                goto done;
            }

            chk = SSL_set_alpn_protos(ssl_qconn, alpn_ossltest, sizeof(alpn_ossltest));
            if (chk != 0) {
                fprintf(stderr, "[ Client ] %s SSL_set_alpn_protos failed %s\n",
                        __func__, ERR_reason_error_string(ERR_get_error()));
                quit = 1;
                goto done;
            }

            chk = SSL_connect(ssl_qconn);
            if (chk != 1) {
                fprintf(stderr, "[ Server ] %s SSL_connect() to %s:%s failed (%s)\n",
                        __func__, dst_host, dst_port_str,
                        ERR_reason_error_string(ERR_get_error()));
                quit = 1;
                goto done;
            }

            SSL_free(ssl_qstream);
            ssl_qstream = SSL_new_stream(ssl_qconn, 0);
            if (ssl_qstream == NULL) {
                fprintf(stderr, "[ Server ] %s SSL_new_stream() to %s:%s failed (%s)\n",
                        __func__, dst_host, dst_port_str,
                        ERR_reason_error_string(ERR_get_error()));
                quit = 1;
                goto done;
            }
            fprintf(stdout, "( Server ) got stream\n");
        }
    }

    send_file(ssl_qstream, path);
    chk = SSL_stream_conclude(ssl_qstream, 0);
    if (chk == 0) {
        fprintf(stdout, "( Server ) %s SSL_stream_conclude(ssl_qstream) %s\n",
                __func__, ERR_reason_error_string(ERR_get_error()));
    }

done:
    SSL_free(ssl_qstream);
    if (ssl_qconn != NULL) {
        while (SSL_shutdown(ssl_qconn) != 1)
            continue;
        SSL_free(ssl_qconn);
    }
    BIO_ADDRINFO_free(bai);
}

/*
 * server handles one connection at a time. There are two nested
 * loops. The outer loop accepts connection from client, the inner
 * loop accepts streams initiated by client and dispatches them
 * to  process_new_stream(). Once client hangs up inner loop
 * terminates and program arrives back to SSL_accept_connection()
 * to handle new connection.
 */
static int run_quic_server(SSL_CTX *ssl_ctx, BIO **bio_sock)
{
    int err = 1;
    int chk;
    SSL *ssl_qlistener, *ssl_qconn, *ssl_qstream;
    unsigned long errcode;

    ssl_qlistener = SSL_new_listener(ssl_ctx, 0);
    if (ssl_qlistener == NULL)
        goto err;

    SSL_set_bio(ssl_qlistener, *bio_sock, *bio_sock);
    *bio_sock = NULL;

    chk = SSL_listen(ssl_qlistener);
    if (chk == 0)
        goto err;

    while (quit == 0) {
        ERR_clear_error();

        fprintf(stdout, "( Server ) Waiting for connection\n");
        ssl_qconn = SSL_accept_connection(ssl_qlistener, 0);
        if (ssl_qconn == NULL) {
            fprintf(stderr, "[ Server ] %s SSL_accept_connection %s\n",
                    __func__, ERR_reason_error_string(ERR_get_error()));
            goto err;
        }
        fprintf(stdout, "( Server ) Accepted new connection\n");

        chk = SSL_set_incoming_stream_policy(ssl_qconn,
                                             SSL_INCOMING_STREAM_POLICY_ACCEPT,
                                             0);
        if (chk == 0) {
            fprintf(stderr, "[ Server ] %s SSL_set_incoming_stream_policy %s\n",
                    __func__, ERR_reason_error_string(ERR_get_error()));
            goto close_conn;
        }

        while (quit == 0) {
            ssl_qstream = SSL_accept_stream(ssl_qconn, 0);
            if (ssl_qstream == NULL) {
                errcode = ERR_get_error();
                if (ERR_GET_REASON(errcode) != SSL_R_PROTOCOL_IS_SHUTDOWN)
                    fprintf(stderr, "[ Server ] %s SSL_accept_stream %s\n",
                            __func__, ERR_reason_error_string(errcode));
                break;
            }
            process_new_stream(ssl_qlistener, ssl_qstream);
        }

    close_conn:
        while (SSL_shutdown(ssl_qconn) != 1)
            continue;

        SSL_free(ssl_qconn);
    }

    err = 0;

err:
    SSL_free(ssl_qlistener);

    return err;
}

/*
 * Read data sent by server over ssl_qstream. Function reports
 * failure if expected size is not received. Argument filename
 * is just for logging here.
 */
static int client_stream_transfer(SSL *ssl_qstream, size_t expected,
                                  const char *filename)
{
    char buf[1024];
    size_t transfered, x;
    int chk;

    transfered = 0;
    while (transfered < expected) {
        fprintf(stdout, "( Client ) reading from stream ... \n");
        chk = SSL_read_ex(ssl_qstream, buf, sizeof(buf), &x);
        if (chk == 0) {
            fprintf(stderr, "[ Client ] %s SSL_read_ex(%s) { %zu } %s\n",
                    __func__, filename, transfered,
                    ERR_reason_error_string(ERR_get_error()));
            return 1;
        }
        fprintf(stdout, "( Client ) got %zu bytes\n", x);
        transfered += x;
    }

    if (transfered != expected) {
        fprintf(stderr, "[ Client ] %s transfer %s incomplete, missing %ld\n",
                __func__, filename, (long)(expected - transfered));
        return 1;
    }

    chk = SSL_read_ex(ssl_qstream, buf, sizeof(buf), &x);
    if (chk != 0) {
        fprintf(stderr, "[ Client ] %s there is more than %zu to receive in %s\n",
                __func__, expected, filename);
        return 1;
    }

    return 0;
}

/*
 * Function requests file filename from server. It sends request over
 * ssl_qstream and reads desired response from ssl_qstream too.
 */
static int client_httplike_transfer(SSL *ssl_qstream, const char *filename)
{
    char buf[1024];
    char *fsize_str, *p;
    size_t fsize, transfered;
    int err = 1;
    int chk;

    strncpy(buf, filename, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    fsize_str = strchr(buf, '_');
    if (fsize_str == NULL) {
        fprintf(stderr, "[ Client ] %s no '_' found in %s\n",
                __func__, filename);
        goto done;
    }

    fsize_str++;
    p = strchr(fsize_str, '.');
    if (p == NULL) {
        fprintf(stderr, "[ Client ] %s no '.' found in %s\n",
                __func__, filename);
        goto done;
    }
    *p = '\0';

    fsize = (size_t)atoi(fsize_str);
    if ((fsize != 0) && (fsize >= FILE_MAX_SZ)) {
        fprintf(stderr, "[ Client ] %s unexpected length in %s\n",
                __func__, filename);
        goto done;
    }

    snprintf(buf, sizeof(buf), "GET /%s\r\n", filename);
    chk = SSL_write_ex(ssl_qstream, buf, strlen(buf), &transfered);
    if (chk == 0) {
        fprintf(stderr, "[ Client ] %s SSL_write_ex('GET /%s') failed %s\n",
                __func__, filename,
                ERR_reason_error_string(ERR_get_error()));
        goto done;
    }

    err = client_stream_transfer(ssl_qstream, fsize, filename);

done:
    return err;
}

/*
 * Function requests file filename from server. It uses ftp-like
 * transfer. The request is sent over `ssl_qstream_cmd`. The
 * response is received from stream which is arranged over yet
 * another QUIC connection. Function uses ssl_qconn_listener to
 * accept a new connection from server. Once server connects
 * function accepts new connection from server to receive data.
 */
static int client_ftplike_transfer(SSL *ssl_qstream_cmd,
                                   SSL *ssl_qconn_listener,
                                   BIO_ADDR *bio_addr,
                                   const char *filename)
{
    char buf[1024];
    char *fsize_str, *p;
    size_t fsize, transfered;
    SSL *ssl_qconn_data = NULL;
    SSL *ssl_qstream_data = NULL;
    int err = 1;
    int chk;
    char *hostip_str = NULL;
    char *port_str = NULL;

    strncpy(buf, filename, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    fsize_str = strchr(buf, '_');
    if (fsize_str == NULL) {
        fprintf(stderr, "[ Client ] no '_' found in %s\n", filename);
        goto done;
    }

    fsize_str++;
    p = strchr(fsize_str, '.');
    if (p == NULL) {
        fprintf(stderr, "[ Client ] no '.' found in %s\n", filename);
        goto done;
    }
    *p = '\0';

    fsize = (size_t)atoi(fsize_str);
    if (fsize <= 0) {
        fprintf(stderr, "[ Client ] %s unexpected length in %s\n",
                __func__, filename);
        goto done;
    }

    /*
     * Active transfer request, server connects back, note the
     * first path component is localhost:port. We use port + 1 where
     * we expect server to connect back.
     */
    hostip_str = BIO_ADDR_hostname_string(bio_addr, 1);
    if (hostip_str == NULL) {
        fprintf(stderr, "[ Client ] BIO_ADDR_hostname_string failed\n");
        goto done;
    }
    port_str = BIO_ADDR_service_string(bio_addr, 1);
    if (port_str == NULL) {
        fprintf(stderr, "[ Client ] BIO_ADDR_service_string failed\n");
        goto done;
    }
    snprintf(buf, sizeof(buf), "GET /%s:%s/%s\r\n", hostip_str, port_str,
             filename);
    chk = SSL_write_ex(ssl_qstream_cmd, buf, strlen(buf), &transfered);
    if (chk == 0) {
        fprintf(stderr, "[ Client ] %s SSL_write_ex() failed %s\n",
                __func__, ERR_reason_error_string(ERR_get_error()));
        goto done;
    }
    /*
     * we are done with transfer command, we must accept stream
     * on data connection to receive file.
     */
    chk = SSL_stream_conclude(ssl_qstream_cmd, 0);
    if (chk == 0) {
        fprintf(stdout, "( Client ) %s SSL_stream_conclude(ssl_qstream) %s\n",
                __func__, ERR_reason_error_string(ERR_get_error()));
    }

    /*
     * accept QUIC connection for data first.
     */
    ssl_qconn_data = SSL_accept_connection(ssl_qconn_listener, 0);
    if (ssl_qconn_data == NULL) {
        fprintf(stderr, "[ Client ] %s SSL_accept_connectio failed %s\n",
                __func__, ERR_reason_error_string(ERR_get_error()));
        goto done;
    }
    /*
     * create data stream to receive data from server.
     */
    ssl_qstream_data = SSL_accept_stream(ssl_qconn_data, 0);
    if (ssl_qstream_data == NULL) {
        fprintf(stderr, "[ Client ] %s SSL_new_stream failed %s\n",
                __func__, ERR_reason_error_string(ERR_get_error()));
        ERR_print_errors_fp(stderr);
        goto done;
    }

    err = client_stream_transfer(ssl_qstream_data, fsize, filename);

    if (err == 0) {
        chk = SSL_stream_conclude(ssl_qstream_data, 0);
        if (chk == 0) {
            fprintf(stdout, "( Client ) %s SSL_stream_conclude(ssl_qstream_data) %s\n",
                    __func__, ERR_reason_error_string(ERR_get_error()));
        }
    }
done:
    SSL_free(ssl_qstream_data);
    while (SSL_shutdown(ssl_qconn_data) != 1)
        continue;
    SSL_free(ssl_qconn_data);

    return err;
}

/*
 * let server know it's time to quit.
 */
static void client_send_quit(SSL *ssl_qconn)
{
    SSL *ssl_qstream;
    int chk;
    size_t w;

    ssl_qstream = SSL_new_stream(ssl_qconn, SSL_STREAM_FLAG_UNI);
    if (ssl_qstream == NULL) {
        chk = SSL_write_ex(ssl_qstream, "QUIT\r\n", sizeof("QUIT\r\n") - 1, &w);
        if (chk == 0) {
            fprintf(stdout, "( Client ) %s SSL_write_ex(ssl_qstream, 'QUIT')) %s\n",
                    __func__, ERR_reason_error_string(ERR_get_error()));
        }
        chk = SSL_stream_conclude(ssl_qstream, 0);
        if (chk == 0) {
            fprintf(stdout, "( Client ) %s SSL_stream_conclude(ssl_qstream) %s\n",
                    __func__, ERR_reason_error_string(ERR_get_error()));
        }
        SSL_free(ssl_qstream);
    } else {
        fprintf(stderr, "[ Client ] %s can not create stream %s\n",
                __func__, ERR_reason_error_string(ERR_get_error()));
    }
}

static int client_run(SSL *ssl_qconn, SSL *ssl_qconn_listener,
                      BIO_ADDR *bio_addr)
{
    SSL *ssl_qstream_cmd;
    const char *filenames[] = {
        "file_1024.txt",
        "file_2048.txt",
        "file_3076.txt",
        "file_4096.txt",
        "file_1234.txt",
        NULL
    };
    const char **filename = filenames;
    int err = 0;

    while (err == 0 && *filename != NULL) {
        ssl_qstream_cmd = SSL_new_stream(ssl_qconn, 0);
        if (ssl_qstream_cmd == NULL) {
            fprintf(stderr, "[ Client ] %s SSL_new_stream failed (%s)\n",
                    __func__, ERR_reason_error_string(ERR_get_error()));
            err = 1;
            continue;
        }

        fprintf(stdout, "( Client ) %s getting %s\n", __func__, *filename);
        if (ssl_qconn_listener == NULL)
            err = client_httplike_transfer(ssl_qstream_cmd, *filename);
        else
            err = client_ftplike_transfer(ssl_qstream_cmd, ssl_qconn_listener,
                                          bio_addr, *filename);
        if (err == 0)
            filename++;

        SSL_free(ssl_qstream_cmd);
    }

    if (err != 0)
        fprintf(stderr, "[ Client ] %s could not get %s\n",
                __func__, *filename);

    return err;
}

static BIO_ADDR *resolve_host_port(const char *host_port)
{
    char *host = NULL;
    char *port_str;
    BIO_ADDR *bio_addr = NULL;
    BIO_ADDRINFO *bai;
    int chk;

    host = strdup(host_port);
    if (host == NULL) {
        perror("malloc");
        return NULL;
    }

    port_str = strchr(host, ':');
    if (port_str == NULL) {
        fprintf(stderr, "missing ':port'\n");
        free(host);
        return NULL;
    }

    chk = BIO_lookup_ex(host, port_str, BIO_LOOKUP_CLIENT, AF_UNSPEC,
                        SOCK_DGRAM, IPPROTO_UDP, &bai);
    if (chk == 0) {
        fprintf(stderr, "host look up failed for %s\n", host_port);
        free(host);
        return NULL;
    }
    free(host);

    bio_addr = BIO_ADDR_dup(BIO_ADDRINFO_address(bai));
    if (bio_addr == NULL)
        perror("BIO_ADDR_new");

    BIO_ADDRINFO_free(bai);

    return bio_addr;
}

/*
 * This is the main() for client, we arrive here right after fork().
 */
static int qclient_main(int argc, const char *argv[])
{
    SSL_CTX *ssl_ctx = NULL;
    SSL_CTX *ssl_ctx_data = NULL;
    BIO *bio_sock = NULL;
    BIO *bio_sock_data = NULL;
    SSL *ssl_qconn = NULL;
    SSL *ssl_qconn_listener = NULL;
    int err = 1;
    int chk;
    BIO_ADDR *bio_addr = NULL;
    struct in_addr ina = { 0 };

    whoami = "Client";

    if (argc != 4) {
        fprintf(stderr, "%s needs hostname:port servercert serverkey\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    bio_addr = resolve_host_port(argv[1]);
    if (bio_addr == NULL)
        return EXIT_FAILURE;

    /*
     * We are creating two QUIC SSL objects here:
     *    - SSL QUIC connection client object
     *    - SSL QUIC listener (server if you want) where remote
     *      QUIC server connects to perform active-FTP like data
     *      transfer
     *
     * create quic connection SSL client object. This involves steps as
     * follows:
     *    - create context for client (no servercert, serverkey are needed)
     *    - create UDP socket for client, although create_socket() calls
     *      bind(2) we let system to bind socket to any addr (ina = { 0 }).
     *    - we create ssl_qconn a quic client connection object
     *    - the ssl_qconn needs to be further initialized:
     *        o Assign a dstIP:dstPort of remote QUIC server where client
     *          connects to
     *        o set application layer protocol negotiation, we use hq-interop
     *        o use SSL_connect() to connect to server.
     */

    /*
     * we create a QUIC client, hence servercert and serverkey are NULL.
     */
    ssl_ctx = create_ctx(NULL, NULL);
    if (ssl_ctx == NULL) {
        fprintf(stderr, "[ Client ]: Failed to create context (%s)\n",
                ERR_reason_error_string(ERR_get_error()));
        goto done;
    }

    bio_sock = create_socket(0, &ina);
    if (bio_sock == NULL) {
        fprintf(stderr, "[ Client ]: could not create socket (%s)\n",
                ERR_reason_error_string(ERR_get_error()));
        goto done;
    }

    ssl_qconn = SSL_new(ssl_ctx);
    if (ssl_qconn == NULL) {
        fprintf(stderr, "[ Client ]: could not create socket (%s)\n",
                ERR_reason_error_string(ERR_get_error()));
        goto done;
    }

    /*
     * pass socket to ssl_qconn object, ssl_qconn uses the socket
     * for reading and writing,
     */
    SSL_set_bio(ssl_qconn, bio_sock, bio_sock);
    bio_sock = NULL;

    chk = SSL_set1_initial_peer_addr(ssl_qconn, bio_addr);
    if (chk == 0) {
        fprintf(stderr, "[ Client ]:  SSL_set1_initial_peer_addr (%s)\n",
                ERR_reason_error_string(ERR_get_error()));
        goto done;
    }

    /*
     * we are hq-interop client.
     */
    chk = SSL_set_alpn_protos(ssl_qconn, alpn_ossltest, sizeof(alpn_ossltest));
    if (chk != 0) {
        fprintf(stderr, "[ Client ] ]: SSL_set_alpn_protos failed %s\n",
                ERR_reason_error_string(ERR_get_error()));
        goto done;
    }

    chk = SSL_connect(ssl_qconn);
    if (chk != 1) {
        fprintf(stderr, "[ Client ]:  SSL_connect (%s)\n",
                ERR_reason_error_string(ERR_get_error()));
        ERR_print_errors_fp(stderr);
        goto done;
    }

    /*
     * Here we create QUIC listener for data received in active-FTP like
     * fashion.
     */
    ssl_ctx_data = create_ctx(argv[2], argv[3]);
    if (ssl_ctx_data == NULL) {
        fprintf(stderr, "[ Client ]: Failed to create data context\n");
        ERR_print_errors_fp(stderr);
        goto done;
    }

    /*
     * Create and bind a UDP socket. Note: we use port number port + 1 for
     * client's listener
     */
    bio_sock_data = create_socket(htons(ntohs(BIO_ADDR_rawport(bio_addr)) + 1),
                                  &ina);
    if (bio_sock_data == NULL) {
        fprintf(stderr, "[ Client ] Failed to create socket\n");
        ERR_print_errors_fp(stderr);
        goto done;
    }

    ssl_qconn_listener = SSL_new_listener(ssl_ctx_data, 0);
    if (ssl_qconn_listener == NULL) {
        fprintf(stderr, "[ Client ] Failed to create listener %s\n",
                ERR_reason_error_string(ERR_get_error()));
        goto done;
    }

    SSL_set_bio(ssl_qconn_listener, bio_sock_data, bio_sock_data);
    bio_sock_data = NULL;

    chk = SSL_listen(ssl_qconn_listener);
    if (chk == 0) {
        fprintf(stderr, "[ Client ] Failed to start listener %s\n",
                ERR_reason_error_string(ERR_get_error()));
        goto done;
    }

    /*
     * passing NULL as a listener makes client to run like
     * http/1.0 client, request and response use bi-directional
     * QUIC-stream.
     * passing a listener makes client to run in active-FTP-like
     * mode. Client sends request over stream to server.
     * Then client waits for server to send response back
     * over yet another QUIC connection. Client accepts the connection
     * from server on `ssl_qcon_listener` QUIC object.
     */
    err = client_run(ssl_qconn, NULL, NULL);
    if (err == 0)
        err = client_run(ssl_qconn, ssl_qconn_listener, bio_addr);

    /*
     * Tell server to stop and finish.
     */
    client_send_quit(ssl_qconn);

    while (SSL_shutdown(ssl_qconn) != 1)
        continue;
done:
    SSL_free(ssl_qconn_listener);
    BIO_free(bio_sock_data);
    SSL_CTX_free(ssl_ctx_data);
    SSL_free(ssl_qconn);
    BIO_free(bio_sock);
    SSL_CTX_free(ssl_ctx);
    BIO_ADDR_free(bio_addr);

    return err;
}

/*
 * main program: * after it forks client it continues to run
 * as a server, until client tells it's time to quit.
 */
static int qserver_main(int argc, const char *argv[])
{
    int res = EXIT_FAILURE;
    SSL_CTX *ssl_ctx = NULL;
    BIO *bio_sock = NULL;
    struct in_addr ina;
    unsigned long server_port;

    ina.s_addr = INADDR_ANY;

    if (argc != 4) {
        fprintf(stderr, "usage: %s <port> <server.crt> <server.key>\n", argv[0]);
        goto out;
    }

    /* Parse port number from command line arguments. */
    server_port = strtoul(argv[1], NULL, 0);
    if ((server_port == 0) || (server_port > UINT16_MAX)) {
        fprintf(stderr, "[ Server ] Failed to parse port number\n");
        goto out;
    }

    /* Create SSL_CTX that supports QUIC. */
    ssl_ctx = create_ctx(argv[2], argv[3]);
    if (ssl_ctx == NULL) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "[ Server ]: Failed to create context\n");
        goto out;
    }

    fprintf(stdout, "( Server ) Binding to port %lu\n", server_port);

    /* Create and bind a UDP socket. */
    bio_sock = create_socket((uint16_t)server_port, &ina);
    if (bio_sock == NULL) {
        fprintf(stderr, "[ Server ] Failed to create socket\n");
        ERR_print_errors_fp(stderr);
        goto out;
    }

    /* QUIC server connection acceptance loop. */
    res = run_quic_server(ssl_ctx, &bio_sock);

out:
    /* Free resources. */
    SSL_CTX_free(ssl_ctx);
    BIO_free(bio_sock);

    return res;
}

int main(int argc, const char *argv[])
{
    if (strcmp(argv[0], "qserver") == 0)
        return qserver_main(argc, argv);
    else if (strcmp(argv[0], "qclient") == 0)
        return qclient_main(argc, argv);

    fprintf(stdout, "SPAM! SPAM! SPAM!\n");

    return 1;
}
