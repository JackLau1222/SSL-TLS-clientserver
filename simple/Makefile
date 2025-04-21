LIBS        = -lssl -lcrypto -pthread -lm -ldl
INCLUDES   = -I/opt/homebrew/Cellar/openssl@3/3.4.1/include
LFLAGS	    = -L/opt/homebrew/Cellar/openssl@3/3.4.1/lib

tls:
	gcc $(INCLUDES) -o tls_server tls_server.c $(LFLAGS) $(LIBS)
	gcc $(INCLUDES) -o tls_client tls_client.c $(LFLAGS) $(LIBS)

dtls:
	gcc $(INCLUDES) -o dtls_server dtls_server.c $(LFLAGS) $(LIBS)
	gcc $(INCLUDES) -o dtls_client dtls_client.c $(LFLAGS) $(LIBS)

clean:
	rm -rf tls_server tls_client dtls_server dtls_client
	