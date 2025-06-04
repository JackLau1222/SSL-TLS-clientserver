#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#define SERVER_CERT_FILE "./cert/server-cert.pem"
#define SERVER_KEY_FILE  "./cert/server-key.pem"
#define CA_CERT_FILE     "./cert/ca-cert.pem"
#define SERVER_ADDR      "/Users/jacklau/Documents/Programs/Git/Github/SSL-TLS-clientserver/test"

#define BUFFER_SIZE 1024

int main(void)
{
    int sockfd, clientfd;
    struct sockaddr_un server_addr;
    socklen_t client_len;
    char buffer[BUFFER_SIZE];
    ssize_t ret;

    gnutls_certificate_credentials_t xcred;
    gnutls_session_t session;

    gnutls_global_init();
    gnutls_global_set_log_level(2); // increase for more detail
    gnutls_certificate_allocate_credentials(&xcred);
    gnutls_certificate_set_x509_trust_file(xcred, CA_CERT_FILE, GNUTLS_X509_FMT_PEM);
    gnutls_certificate_set_x509_key_file(xcred, SERVER_CERT_FILE, SERVER_KEY_FILE, GNUTLS_X509_FMT_PEM);

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    unlink(SERVER_ADDR);
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SERVER_ADDR, sizeof(server_addr.sun_path) - 1);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(sockfd);
        return 1;
    }

    if (listen(sockfd, 1) < 0) {
        perror("listen");
        close(sockfd);
        return 1;
    }

    printf("Waiting for client connection...\n");
    client_len = sizeof(server_addr);
    clientfd = accept(sockfd, (struct sockaddr *)&server_addr, &client_len);
    if (clientfd < 0) {
        perror("accept");
        close(sockfd);
        return 1;
    }

    gnutls_init(&session, GNUTLS_SERVER);
    gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
    gnutls_set_default_priority(session);
    gnutls_transport_set_int(session, clientfd);

    ret = gnutls_handshake(session);
    if (ret < 0) {
        fprintf(stderr, "Handshake failed: %s\n", gnutls_strerror(ret));
        gnutls_deinit(session);
        close(clientfd);
        close(sockfd);
        return 1;
    }

    printf("TLS handshake completed. Waiting for client message...\n");

    ret = gnutls_record_recv(session, buffer, sizeof(buffer));
    if (ret >= 0) {
        printf("Client sent: %s\n", buffer);
        gnutls_record_send(session, buffer, strlen(buffer) + 1);
    } else {
        fprintf(stderr, "Receive failed: %s\n", gnutls_strerror(ret));
    }

    gnutls_bye(session, GNUTLS_SHUT_RDWR);
    gnutls_deinit(session);
    close(clientfd);
    close(sockfd);
    gnutls_certificate_free_credentials(xcred);
    gnutls_global_deinit();

    return 0;
}
