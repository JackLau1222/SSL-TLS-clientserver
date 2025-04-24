#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static int tcp_connect(const char *host, int port) {
    struct hostent *he = gethostbyname(host);
    if (!he) return -1;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    memcpy(&addr.sin_addr, he->h_addr, he->h_length);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(sock);
        return -1;
    }
    return sock;
}

int main(void) {
    const char *host = "raw.githubusercontent.com";
    const int   port = 443;
    const char *req  =
        "GET /JackLau1222/hls_test/refs/heads/main/stream_1/index.m3u8 HTTP/1.1\r\n"
        "User-Agent: Lavf/62.0.100\r\n"
        "Accept: */*\r\n"
        "Range: bytes=0-\r\n"
        "Connection: keep-alive\r\n"
        "Host: raw.githubusercontent.com\r\n"
        // "Connection: close\r\n"
        "Icy-MetaData: 1\r\n"
        "\r\n";

    /* 1. Init OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    const SSL_METHOD *meth = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(meth);

    /* 2. TCP connect */
    int sock = tcp_connect(host, port);
    if (sock < 0) {
        perror("tcp_connect");
        return 1;
    }

    /* 3. SSL setup */
    SSL *ssl = SSL_new(ctx);
    SSL_set_tlsext_host_name(ssl, host);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    printf("Connected with %s encryption\n", SSL_get_cipher(ssl));

    /* 4. Send HTTP request */
    SSL_write(ssl, req, strlen(req));

    /* 5. First read() – likely to return headers (or part of them) */
    {
        char buf[4096] = {0};
        int n = SSL_read(ssl, buf, sizeof(buf)-1);
        if (n > 0) {
            printf("=== First SSL_read() returned %d bytes ===\n", n);
            fwrite(buf, 1, n, stdout);
            printf("\n=========================================\n\n");
        }
    }

    /* 6. Second read() – next bytes (body) */
    {
        char buf[4096] = {0};
        int n = SSL_read(ssl, buf, sizeof(buf)-1);
        if (n > 0) {
            printf("=== Second SSL_read() returned %d bytes ===\n", n);
            fwrite(buf, 1, n, stdout);
            printf("\n==========================================\n");
        }
    }

    /* Cleanup */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    return 0;
}
