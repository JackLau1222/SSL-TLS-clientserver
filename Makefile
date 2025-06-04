LIBS        = -lssl -lcrypto -pthread -lm -ldl
# INCLUDES   = -I/opt/homebrew/Cellar/openssl@3/3.4.1/include
# LFLAGS	    = -L/opt/homebrew/Cellar/openssl@3/3.4.1/lib

libssl:
	gcc $(INCLUDES) -o server ssl_server_libssl.c $(LFLAGS) $(LIBS)
	gcc $(INCLUDES) -o client ssl_client_libssl.c $(LFLAGS) $(LIBS)
polarssl:
	gcc -o server ssl_server_polarssl.c -lpolarssl -L../lib -I../include
	gcc -o client ssl_client_polarssl.c -lpolarssl -L../lib -I../include

clean:
	rm -rf server client
	

