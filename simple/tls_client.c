#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_IP   "127.0.0.1"
#define SERVER_PORT 4443
#define CA_FILE     "../cert/ca-cert.pem"
#define CERT_FILE "../cert/client-cert.pem"
#define KEY_FILE  "../cert/client-key.pem"

int main() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());        // TLS client method :contentReference[oaicite:2]{index=2}
    SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx,  KEY_FILE,  SSL_FILETYPE_PEM);
    SSL_CTX_check_private_key(ctx);

    SSL_CTX_load_verify_locations(ctx, CA_FILE, NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(SERVER_PORT) };
    inet_pton(AF_INET, SERVER_IP, &addr.sin_addr);
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {                             // do TLS handshake
        ERR_print_errors_fp(stderr);
    } else {
        char buf[256];
        int len = SSL_read(ssl, buf, sizeof(buf)-1);
        buf[len] = '\0';
        printf("Received: %s", buf);
        SSL_shutdown(ssl);
    }

    close(sock);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
