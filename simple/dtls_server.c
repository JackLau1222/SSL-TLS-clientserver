#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 23232
#define CERT_FILE "../cert/server-cert.pem"
#define KEY_FILE  "../cert/server-key.pem"

// Simple cookie callbacks (just echo client IP/port)
static int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
    BIO *rbio = SSL_get_rbio(ssl);
    struct sockaddr_storage peer;
    socklen_t plen = sizeof(peer);
    BIO_dgram_get_peer(rbio, &peer);
    memcpy(cookie, &peer, plen>sizeof(peer)?sizeof(peer):plen);
    *cookie_len = plen;
    return 1;
}
static int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
    // in real use, recompute and compare
    return 1;
}

int main() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(DTLS_server_method());       // DTLS method :contentReference[oaicite:3]{index=3}
    SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM);
    SSL_CTX_set_options(ctx, SSL_OP_COOKIE_EXCHANGE);       // enable cookie exchange :contentReference[oaicite:4]{index=4}
    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr = { .sin_family=AF_INET, .sin_port=htons(PORT) };
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(sock, (struct sockaddr*)&addr, sizeof(addr));

    BIO *bio = BIO_new_dgram(sock, BIO_NOCLOSE);
    SSL *ssl = SSL_new(ctx);
    SSL_set_bio(ssl, bio, bio);

    if (SSL_accept(ssl) <= 0) {                              // DTLS handshake + cookie
        ERR_print_errors_fp(stderr);
    } else {
        SSL_write(ssl, "Hello, DTLS!\n", strlen("Hello, DTLS!\n"));
        SSL_shutdown(ssl);
    }

    close(sock);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
