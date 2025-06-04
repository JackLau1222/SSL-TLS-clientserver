#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#define CLIENT_CERT_FILE "./cert/client-cert.pem"
#define CLIENT_KEY_FILE  "./cert/client-key.pem"
#define CA_CERT_FILE     "./cert/ca-cert.pem"
#define SERVER_ADDR      "/Users/jacklau/Documents/Programs/Git/Github/SSL-TLS-clientserver/test"

#define BUFFER_SIZE 1024

int main(void)
{
    int sockfd;
    struct sockaddr_un server_addr;
    char buffer[BUFFER_SIZE] = "Client Hello World";
    ssize_t ret;

    gnutls_certificate_credentials_t xcred;
    gnutls_session_t session;

    gnutls_global_init();

    gnutls_certificate_allocate_credentials(&xcred);
    gnutls_certificate_set_x509_trust_file(xcred, CA_CERT_FILE, GNUTLS_X509_FMT_PEM);
    gnutls_certificate_set_x509_key_file(xcred, CLIENT_CERT_FILE, CLIENT_KEY_FILE, GNUTLS_X509_FMT_PEM);

    gnutls_init(&session, GNUTLS_CLIENT);
    gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

    gnutls_server_name_set(session, GNUTLS_NAME_DNS, "localhost", strlen("localhost"));
    gnutls_set_default_priority(session);

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SERVER_ADDR, sizeof(server_addr.sun_path) - 1);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return 1;
    }

    gnutls_transport_set_int(session, sockfd);

    ret = gnutls_handshake(session);
    if (ret < 0) {
        fprintf(stderr, "Handshake failed: %s\n", gnutls_strerror(ret));
        gnutls_deinit(session);
        close(sockfd);
        return 1;
    }

    printf("Handshake successful. TLS version: %s\n", gnutls_protocol_get_name(gnutls_protocol_get_version(session)));

    ret = gnutls_record_send(session, buffer, strlen(buffer) + 1);
    if (ret < 0) {
        fprintf(stderr, "Send failed: %s\n", gnutls_strerror(ret));
    }

    ret = gnutls_record_recv(session, buffer, sizeof(buffer));
    if (ret >= 0)
        printf("TLS server sent: %s\n", buffer);
    else
        fprintf(stderr, "Receive failed: %s\n", gnutls_strerror(ret));

    gnutls_bye(session, GNUTLS_SHUT_RDWR);
    gnutls_deinit(session);
    close(sockfd);
    gnutls_certificate_free_credentials(xcred);
    gnutls_global_deinit();

    return 0;
}
