#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define SSL_SERVER_RSA_CERT	"./cert/server-cert.pem"
#define SSL_SERVER_RSA_KEY	"./cert/server-key.pem"
#define SSL_SERVER_RSA_CA_CERT	"./cert/ca-cert.pem"
#define SSL_SERVER_RSA_CA_PATH	"./cert/"

#define SSL_SERVER_ADDR		"/Users/jacklau/Documents/Programs/Git/Github/SSL-TLS-clientserver/test"

#define OFF	0
#define ON	1

static void openssl_dtls_on_info(const SSL *dtls, int where, int r0)
{
	printf("DTLS info method=empty state=%s(%s)\n", SSL_state_string(dtls), SSL_state_string_long(dtls));
}

int main(void)
{
	int verify_peer = ON;
	SSL_METHOD *server_meth;
	SSL_CTX *ssl_server_ctx;
	int serversocketfd;
	int clientsocketfd;
	struct sockaddr_un serveraddr;
	int handshakestatus;

	SSL_library_init();
	SSL_load_error_strings();
	//server_meth = SSLv3_server_method();
	server_meth = TLS_server_method();
	ssl_server_ctx = SSL_CTX_new(server_meth);
	
	if(!ssl_server_ctx)
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}
	
	if(SSL_CTX_use_certificate_file(ssl_server_ctx, SSL_SERVER_RSA_CERT, SSL_FILETYPE_PEM) <= 0)	
	{
		ERR_print_errors_fp(stderr);
		return -1;		
	}

	
	if(SSL_CTX_use_PrivateKey_file(ssl_server_ctx, SSL_SERVER_RSA_KEY, SSL_FILETYPE_PEM) <= 0)	
	{
		ERR_print_errors_fp(stderr);
		return -1;		
	}
	
	if(SSL_CTX_check_private_key(ssl_server_ctx) != 1)
	{
		printf("Private and certificate is not matching\n");
		return -1;
	}	

	if(verify_peer)
	{	
		//See function man pages for instructions on generating CERT files
		if(!SSL_CTX_load_verify_locations(ssl_server_ctx, SSL_SERVER_RSA_CA_CERT, NULL))
		{
			ERR_print_errors_fp(stderr);
			return -1;		
		}
		SSL_CTX_set_verify(ssl_server_ctx, SSL_VERIFY_PEER, NULL);
		SSL_CTX_set_verify_depth(ssl_server_ctx, 1);
	}

	if((serversocketfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
	{
		printf("Error on socket creation\n");
		return -1;
	}
	unlink(SSL_SERVER_ADDR);

	memset(&serveraddr, 0, sizeof(struct sockaddr_un));
	serveraddr.sun_family = AF_UNIX;
	//serveraddr.sun_path[0] = 0;
	strncpy(&(serveraddr.sun_path), SSL_SERVER_ADDR, sizeof(serveraddr.sun_path) - 1);
	// 3) Bind: the kernel will *create* the socket file for you
	socklen_t len = offsetof(struct sockaddr_un, sun_path)
				+ strlen(serveraddr.sun_path) + 1;
	// if(bind(serversocketfd, (struct sockaddr *)&serveraddr, sizeof(struct sockaddr_un)))
	if (bind(serversocketfd,
         (struct sockaddr *)&serveraddr,
         len) < 0)
	{
		perror("bind");
		//printf("server bind error\n");
		return -1;
	}
	
	if(listen(serversocketfd, SOMAXCONN))
	{
		printf("Error on listen\n");
		return -1;
	}	
	while(1)
	{
		SSL *serverssl;
		char buffer[1024];
		int bytesread = 0;
		int addedstrlen;
		int ret;
	
		clientsocketfd = accept(serversocketfd, NULL, 0);
		serverssl = SSL_new(ssl_server_ctx);

		SSL_set_ex_data(serverssl, 0, ssl_server_ctx);
		SSL_set_info_callback(serverssl, openssl_dtls_on_info);
		if(!serverssl)
		{
			printf("Error SSL_new\n");
			return -1;
		}
		SSL_set_fd(serverssl, clientsocketfd);
		
		if((ret = SSL_accept(serverssl))!= 1)
		{
			printf("Handshake Error %d\n", SSL_get_error(serverssl, ret));
			return -1;
		}
		
		if(verify_peer)
		{
			X509 *ssl_client_cert = NULL;

			ssl_client_cert = SSL_get_peer_certificate(serverssl);
			
			if(ssl_client_cert)
			{
				long verifyresult;

				verifyresult = SSL_get_verify_result(serverssl);
				if(verifyresult == X509_V_OK)
					printf("Certificate Verify Success\n"); 
				else
					printf("Certificate Verify Failed\n"); 
				X509_free(ssl_client_cert);				
			}
			else
				printf("There is no client certificate\n");
		}
		bytesread = SSL_read(serverssl, buffer, sizeof(buffer));
		addedstrlen = strlen("Appended by SSL server");
		strncpy(&buffer[bytesread], "Appended by SSL server", addedstrlen);
		buffer[bytesread +  addedstrlen ] = '\0';
		SSL_write(serverssl, buffer, bytesread + addedstrlen + 1);
		SSL_shutdown(serverssl);
		close(clientsocketfd);
		clientsocketfd = -1;
		SSL_free(serverssl);
		serverssl = NULL;
	}	
	close(serversocketfd);
	SSL_CTX_free(ssl_server_ctx);
	return 0;	
}
