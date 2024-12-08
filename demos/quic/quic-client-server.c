/*
 *  Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License").  You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 */


#include <string.h>
#include <strings.h>

#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/quic.h>

#include "file_list.h"

#define BUF_SIZE 4096

#define LOCALHOST_IP 0x7f000001

/*
 * hq-interop application protocol
 */
static const unsigned char alpn_ossltest[] = {
    10, 'h', 'q', '-', 'i', 'n', 't', 'e', 'r', 'o', 'p',
};
static const char *whoami = "Server";
static unsigned long port;
static int quit;
static enum {
    ACTIVE,
    PASSIVE
} mode;

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
    SSL_CTX *ctx;

    if (cert_path == NULL && key_path == NULL) {
        ctx = SSL_CTX_new(OSSL_QUIC_client_method());
        if (ctx == NULL)
            goto err;

    } else {
        ctx = SSL_CTX_new(OSSL_QUIC_server_method());
        if (ctx == NULL)
            goto err;
        SSL_CTX_set_alpn_select_cb(ctx, select_alpn, NULL);
    }

    if (cert_path != NULL && SSL_CTX_use_certificate_chain_file(ctx, cert_path) <= 0) {
        fprintf(stderr, "[ %s ] couldn't load certificate file: %s\n", whoami, cert_path);
        goto err;
    }

    if (key_path != NULL && SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "[ %s ] couldn't load key file: %s\n", whoami, key_path);
        goto err;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    return ctx;

err:
    SSL_CTX_free(ctx);
    return NULL;
}

static BIO *create_socket(uint16_t port, struct in_addr *ina)
{
    int fd = -1;
    struct sockaddr_in sa;
    BIO *sock = NULL;
    int i;

    if ((fd = BIO_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0)) < 0) {
        fprintf(stderr, "[ %s ]cannot create socket", whoami);
        goto err;
    }

    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr = *ina;
    if (bind(fd, (const struct sockaddr *)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "[ %s ] cannot bind to %u\n", whoami, port);
        goto err;
    }

    sock = BIO_new(BIO_s_datagram());
    if (sock == NULL) {
        fprintf(stderr, "[ %s ] cannot create dgram bio\n", whoami);
        goto err;
    }

    if (!BIO_set_fd(sock, fd, BIO_CLOSE)) {
        fprintf(stderr, "[ %s ] Unable to set fd of dgram sock\n", whoami);
        goto err;
    }

    return sock;

err:
    BIO_free(sock);
    BIO_closesocket(fd);
    return NULL;
}

static void send_file(SSL *stream, const char *filename)
{
    unsigned char buf[BUF_SIZE];
    BIO *readbio;
    size_t bytes_read = 0;
    size_t bytes_written = 0;
    size_t offset = 0;
    int rc;

    fprintf(stdout, "( Server ) Serving %s\n", filename);
    readbio = BIO_new_file(filename, "r");
    if (readbio == NULL) {
        fprintf(stderr, "[ Server ] Unable to open %s\n", filename);
        ERR_print_errors_fp(stderr);
        goto done;
    }

    while (BIO_eof(readbio) <= 0) {
        bytes_read = 0;
        if (!BIO_read_ex(readbio, buf, BUF_SIZE, &bytes_read)) {
            if (BIO_eof(readbio) <= 0) {
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
            rc = SSL_write_ex(stream, &buf[offset], bytes_read, &bytes_written);
            if (rc <= 0) {
                rc = SSL_get_error(stream, rc);
                switch (rc) {
                case SSL_ERROR_WANT_WRITE:
                    fprintf(stderr, "[ Server ] Send buffer full, retrying\n");
                    continue;
                    break;
                default:
                    fprintf(stderr, "[ Server ] Unhandled error cause %d\n", rc);
                    goto done;
                    break;
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
    BIO_free(readbio);

    return;
}

static void process_new_stream(SSL *stream)
{
    unsigned char buf[BUF_SIZE];
    char path[BUF_SIZE];
    char *req = (char *)buf;
    char *reqname;
    char *dst_host;
    char *dst_port_str;
    size_t nread;
    char *creturn;

    memset(buf, 0, BUF_SIZE);
    if (SSL_read_ex(stream, buf, sizeof(buf) - 1, &nread) <= 0)
        return;

    fprintf(stdout, "(Server) Request is %s\n", req);

    reqname = strrchr(req, '/');
    if (reqname == NULL) {
        quit = 1;
        return;
    }
    reqname++;
    creturn = strchr(reqname, '\r');
    *creturn = '\0';
    snprintf(path, BUF_SIZE, "%s", reqname);

    send_file(stream, path);
    SSL_stream_conclude(stream, 0);
    SSL_free(stream);
}

static int run_quic_server(SSL_CTX *ctx, BIO *sock)
{
    int ok = 0;
    SSL *listener, *conn, *stream;
    unsigned long errcode;

    if ((listener = SSL_new_listener(ctx, 0)) == NULL)
        goto err;

    SSL_set_bio(listener, sock, sock);

    if (!SSL_listen(listener))
        goto err;

    while (quit == 0) {
        ERR_clear_error();

        printf("( Server ) Waiting for connection\n");
        conn = SSL_accept_connection(listener, 0);

        if (!SSL_set_default_stream_mode(conn, SSL_DEFAULT_STREAM_MODE_NONE)) {
            fprintf(stderr, "[ Server ]:  SSL_set_default_stream_mode (%s)\n",
                    ERR_reason_error_string(ERR_get_error()));
            goto err;
        }

        if (conn == NULL) {
            fprintf(stderr, "[ Server ] error while accepting connection\n");
            goto err;
        }
        printf("( Server ) Accepted new connection\n");

        for (;;) {
            printf("( Server ) Going to create stream\n");
            if (mode == ACTIVE)
                stream = SSL_new_stream(conn, 0);
            else
                stream = SSL_accept_stream(conn, 0);
            if (stream == NULL) {
                errcode = ERR_get_error();
                if (ERR_GET_REASON(errcode) != SSL_R_PROTOCOL_IS_SHUTDOWN)
                    fprintf(stderr, "[ Server ] Failure in accept stream, error %s\n",
                            ERR_reason_error_string(errcode));
                break;
            }
            process_new_stream(stream);
        }

close_conn:
        while (SSL_shutdown(conn) != 1)
            continue;

        SSL_free(conn);
    }

    ok = 1;

err:
    SSL_free(listener);
    return ok;
}

int client_transfer(SSL *ssl_stream, const char *filename)
{
    char buf[1024];
    char *fsize_str, *p;
    size_t fsize, transfered, x;
    int err = 1;

    strlcpy(buf, filename, sizeof(buf) - 1);
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
    if (fsize == 0) {
        fprintf(stderr, "[ Client ] unexpected length in %s\n", filename);
        goto done;
    }
 
    snprintf(buf, sizeof(buf), "GET /%s\r\n", filename);
    if (!SSL_write_ex(ssl_stream, buf, strlen(buf), &transfered)) {
        fprintf(stderr, "[ Client ] SSL_write_ex() failed %s\n",
                ERR_reason_error_string(ERR_get_error()));
        goto done;
    }

    transfered = 0;
    while (transfered < fsize) {
        if (!SSL_read_ex(ssl_stream, buf, sizeof(buf), &x)) {
            fprintf(stderr, "[ Client ] SSL_read_ex(%s) { %lu } %s\n",
                    filename, transfered,
                    ERR_reason_error_string(ERR_get_error()));
            goto done;
        }
        transfered += x;
    }

    if (transfered != fsize
        || SSL_read_ex(ssl_stream, buf, sizeof(buf), &x) != 0) {
        fprintf(stderr, "[ Client ] there is more than %lu to receive\n", fsize);
        goto done;
    }

    err = 0;
done:
    return err;
}


void client_send_quit(SSL *ssl_qconn)
{
    SSL *ssl_stream;

    ssl_stream = SSL_new_stream(ssl_qconn, SSL_STREAM_FLAG_UNI);
    if (ssl_stream != NULL) {
        SSL_write(ssl_stream, "QUIT\r\n", sizeof("QUIT\r\n") - 1);
        SSL_stream_conclude(ssl_stream, 0);
        SSL_free(ssl_stream);
    } else {
        fprintf(stderr, "[ Client ] %s can not create stream %s\n",
                __func__, ERR_reason_error_string(ERR_get_error()));
    }
}

int client_create_stream(SSL *ssl_qconn)
{
    SSL *ssl_stream;
    const char **filename = files;
    int err = 0;

    while (err == 0 && *filename != NULL) {
        printf("( Client ) going to create stream\n");
        if (mode == ACTIVE)
            ssl_stream = SSL_accept_stream(ssl_qconn, 0);
        else
            ssl_stream = SSL_new_stream(ssl_qconn, 0);

        if (ssl_stream == NULL) {
            fprintf(stderr, "[ Client ] %s SSL_new_stream failed (%s)\n",
                    __func__, ERR_reason_error_string(ERR_get_error()));
            err = 1;
            continue;
        }

        fprintf(stdout, "( Client ) %s getting %s\n", __func__, *filename);
        err = client_transfer(ssl_stream, *filename);
        if (err == 0)
            filename++;

        SSL_free(ssl_stream);
    }

    if (err != 0)
        fprintf(stderr, "[ Client ] %s could not get %s\n", __func__, *filename);

    return err;
}

int client_main(int argc, char *argv[])
{
    SSL_CTX *ctx = NULL;
    BIO *bio_sock = NULL;
    SSL *ssl_qconn = NULL;
    int err = 1;
    struct in_addr ina = { 0 };
    BIO_ADDR *addr;

    whoami = "Client";

    /*
     * we create a QUIC client, hence servercert and serverkey are NULL.
     */
    ctx = create_ctx(NULL, NULL);
    if (ctx == NULL) {
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

    ssl_qconn = SSL_new(ctx);
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

    /*
     * Set up a destination address where client connects to.
     */
    ina.s_addr = htonl(LOCALHOST_IP);
    addr = BIO_ADDR_new();
    if (addr == NULL) {
        fprintf(stderr, "[ Client ]: failed to allocate BIO_ADDR\n");
        goto done;
    }
    if (!BIO_ADDR_rawmake(addr, AF_INET, &ina, sizeof(ina), htons((uint16_t)port))) {
        fprintf(stderr, "[ Client ]: BIO_ADDR_rawmake %s\n",
                ERR_reason_error_string(ERR_get_error()));
        goto done;
    }
    if (!SSL_set1_initial_peer_addr(ssl_qconn,addr)) {
        fprintf(stderr, "[ Client ]:  SSL_set1_initial_peer_addr (%s)\n",
                 ERR_reason_error_string(ERR_get_error()));
        goto done;
    }

    if (SSL_set_default_stream_mode(ssl_qconn, SSL_DEFAULT_STREAM_MODE_NONE) == 0) {
        fprintf(stderr, "[ Client ]:  SSL_set_default_stream_mode (%s)\n",
                 ERR_reason_error_string(ERR_get_error()));
        goto done;
    }

    /*
     * we are hq-interop client.
     */
    if (SSL_set_alpn_protos(ssl_qconn, alpn_ossltest, sizeof(alpn_ossltest)) != 0) {
        fprintf(stderr, "[ Client ] ]: SSL_set_alpn_protos failed %s\n",
                ERR_reason_error_string(ERR_get_error()));
        goto done;
    }

    if (SSL_connect(ssl_qconn) < 1) {
        fprintf(stderr, "[ Client ]:  SSL_connect (%s)\n",
                 ERR_reason_error_string(ERR_get_error()));
        ERR_print_errors_fp(stderr);
        goto done;
    }

    err = client_create_stream(ssl_qconn);

    /*
     * Tell server to stop and finish.
     */
    client_send_quit(ssl_qconn);

    SSL_shutdown(ssl_qconn);
done:
    SSL_free(ssl_qconn);
    BIO_free(bio_sock);
    SSL_CTX_free(ctx);
    BIO_ADDR_free(addr);

    return err;
}

int main(int argc, char *argv[])
{
    int res = EXIT_FAILURE;
    SSL_CTX *ctx = NULL;
    BIO *sock = NULL;
    struct in_addr ina;

    ina.s_addr = INADDR_ANY;

    if (argc != 5) {
        fprintf(stderr, "usage: %s <port> <server.crt> <server.key> <mode>\n", argv[0]);
        goto out;
    }

    if (strcasecmp(argv[4], "active") == 0)
        mode = ACTIVE;
    else if (strcasecmp(argv[4], "passive") == 0)
        mode = PASSIVE;
    else {
        fprintf(stderr, "unknown mode. mode must be 'active' or 'passive'\n");
        goto out;
    }

    /* Create SSL_CTX that supports QUIC. */
    if ((ctx = create_ctx(argv[2], argv[3])) == NULL) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "[ Server ]: Failed to create context\n");
        goto out;
    }

    /* Parse port number from command line arguments. */
    port = strtoul(argv[1], NULL, 0);
    if (port == 0 || port > UINT16_MAX) {
        fprintf(stderr, "[ Server ] Failed to parse port number\n");
        goto out;
    }
    fprintf(stdout, "( Server ) Binding to port %lu\n", port);

    /* Create and bind a UDP socket. */
    if ((sock = create_socket((uint16_t)port, &ina)) == NULL) {
        fprintf(stderr, "[ Server ] Failed to create socket\n");
        ERR_print_errors_fp(stderr);
        goto out;
    }

    if (fork() == 0) {
        SSL_CTX_free(ctx);
        BIO_free(sock);
        return (client_main(argc, argv));
    }

    /* QUIC server connection acceptance loop. */
    if (!run_quic_server(ctx, sock)) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "[ Server ] Failed to run quic server\n");
        goto out;
    }

    wait(NULL);

    res = EXIT_SUCCESS;
out:
    /* Free resources. */
    SSL_CTX_free(ctx);
    BIO_free(sock);
    return res;
}
