#include "openssl/ssl.h"
#include "openssl/bio.h"
#include "openssl/err.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

int main()
{
    BIO * bio;
    SSL * ssl;
    SSL_CTX * ctx;
    
    int sockfd;
	int len;
	struct sockaddr_in address;
	int result=0;
	char ch = 'A';

    int p;

    char * request = "GET / HTTP/1.1\x0D\x0AHost: localhost\x0D\x0A\x43onnection: Close\x0D\x0A\x0D\x0A";
    char r[1024];

    /* Set up the library */

    ERR_load_BIO_strings();
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    /* Set up the SSL context */

    ctx = SSL_CTX_new(SSLv23_client_method());

    /* Load the trust store */

    if(! SSL_CTX_load_verify_locations(ctx, "TrustStore.pem", NULL))
    {
        fprintf(stderr, "Error loading trust store\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return 0;
    }

    /* Setup the connection 

	bio = BIO_new_ssl_connect(ctx);

    /* Set the SSL_MODE_AUTO_RETRY flag 

    BIO_get_ssl(bio, & ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    /* Create and setup the connection 

    BIO_set_conn_hostname(bio, "localhost:4422");

    if(BIO_do_connect(bio) <= 0)
    {
        fprintf(stderr, "Error attempting to connect\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 0;
    }
    
    /* Check the certificate */

	//socket for client
	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	//naming socket
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = inet_addr("127.0.0.1");
	address.sin_port = htons(9738);
	len = sizeof(address);
	printf("length=%d\n",len);
	printf("Socket done\n");

    //connecting server
	result = connect(sockfd, (struct sockaddr *)&address, len);
	if(result <0)
	{
		perror("oops: client\n");
		exit(1);
	}
	else
	{
		printf("Socket Connected\n");
	}
	ssl = SSL_new(ctx);
	BIO *sbio;
	sbio = BIO_new(BIO_s_socket());
	BIO_set_fd(sbio, sockfd, BIO_NOCLOSE);
	SSL_set_bio(ssl, sbio, sbio);
	//SSL_CTX_set_verify_depth(ctx, 1);
	//SSL_set_fd(ssl, sockfd);
	result = SSL_connect(ssl);
	printf("SSL_connect: %d\n", result);
	
	if(SSL_get_verify_result(ssl) != X509_V_OK)
    {
        fprintf(stderr, "Certificate verification error: %i\n", SSL_get_verify_result(ssl));
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 0;
    }
    
    SSL_read(ssl, &ch, 1);
	printf("char from server = %c\n", ch);
	SSL_shutdown(ssl);  
	close(sockfd);
	exit(0);
    
    
    /*for(;;)
    {
        p = BIO_read(bio, r, 1023);
        if(p <= 0) break;
        r[p] = 0;
        printf("%s", r);
    }
    
    FILE *fp = NULL;
	while (fp == NULL) {
		fp = fopen("/home/herat/Downloads/openssl-backup/shared","r");
	}
	remove("/home/herat/Downloads/openssl-backup/shared");*/

    /* Send the request */

    //BIO_write(bio, request, strlen(request));

    /* Read in the response */

    /*for(;;)
    {
        p = BIO_read(bio, r, 1023);
        if(p <= 0) break;
        r[p] = 0;
        printf("%s", r);
    }

    /* Close the connection and free the context 

    BIO_free_all(bio);
    SSL_CTX_free(ctx);*/
    return 0;
}
