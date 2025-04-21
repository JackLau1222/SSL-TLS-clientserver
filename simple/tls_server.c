#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 4443
#define CERT_FILE "../cert/server-cert.pem"
#define KEY_FILE  "../cert/server-key.pem"

int main() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());         // TLS method :contentReference[oaicite:0]{index=0}
    SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM);
    SSL_CTX_check_private_key(ctx);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(PORT) };
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    listen(sock, 1);

    int client = accept(sock, NULL, NULL);
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client);                                 // attach TCP socket :contentReference[oaicite:1]{index=1}

    if (SSL_accept(ssl) <= 0) {                              // do TLS handshake
        ERR_print_errors_fp(stderr);
    } else {
        SSL_write(ssl, "Hello, world!\n", strlen("Hello, world!\n"));
        SSL_shutdown(ssl);
    }

    close(client);
    close(sock);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
