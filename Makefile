LIBS        = -lssl -lcrypto -pthread -lm -ldl
# INCLUDES   = -I/opt/homebrew/Cellar/openssl@3/3.4.1/include
# LFLAGS	    = -L/opt/homebrew/Cellar/openssl@3/3.4.1/lib

libssl:
	gcc $(INCLUDES) -o server tls_server_libssl.c $(LFLAGS) $(LIBS)
	gcc $(INCLUDES) -o client tls_client_libssl.c $(LFLAGS) $(LIBS)
polarssl:
	gcc -o server tls_server_polarssl.c -lpolarssl -L../lib -I../include
	gcc -o client tls_client_polarssl.c -lpolarssl -L../lib -I../include
gnutls:
	gcc -o server tls_server_gnutls.c $(shell pkg-config --cflags --libs gnutls)
	gcc -o client tls_client_gnutls.c $(shell pkg-config --cflags --libs gnutls)

clean:
	rm -rf server client
	

