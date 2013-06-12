#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

extern char  __data_start, __bss_start,_edata,_end; 
SSL_CTX *ctx;
SSL *ssl;
BIO *bio, *abio, *out, *sbio;
int p;
char r[1024];
int server_sockfd, client_sockfd;
int server_len, client_len;
struct sockaddr_in server_address;
struct sockaddr_in client_address;

int result = 0;
char ch = 'a';

int password_callback(char *buf, int size, int rwflag, void *userdata)
{
    /* For the purposes of this demonstration, the password is "ibmdw" */
    printf("*** Callback function called\n");
    strcpy(buf, "ibmdw");
    return 1;
}
    
int (*callback)(char *, int, int, void *) = &password_callback;

int main(int argc, char **argv)
{
    printf("%d",argc);
    
    printf("    Data Start  %10p\n", &__data_start);
    printf("    Data End  %10p\n", &_edata);
    printf("    BSS Start %10p\n", &__bss_start);
    printf("    BSS End %10p\n", &_end);
    
    printf("Secure Programming with the OpenSSL API, Part 4:\n");
    printf("Serving it up in a secure manner\n\n");
    
    SSL_load_error_strings();
	ERR_load_BIO_strings();
	ERR_load_SSL_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
    
    if(argc == 1)
    {
		FILE * fp;		
		///////////////////////////////////////
		//unnamed socket
		server_sockfd = socket(AF_INET, SOCK_STREAM, 0);

		//naming
		server_address.sin_family = AF_INET;
		server_address.sin_addr.s_addr = htonl(INADDR_ANY);
		server_address.sin_port = htons(9738);
		server_len = sizeof(server_address);
		result = bind(server_sockfd, (struct sockaddr *)&server_address, server_len);
		
		///
		printf("Attempting to create SSL context... ");
		ctx = SSL_CTX_new(SSLv23_server_method());
		
		if(ctx == NULL)
		{
			printf("Failed. Aborting.\n");
			return 0;
		}

		printf("\nLoading certificates...\n");
		SSL_CTX_set_default_passwd_cb(ctx, callback);
		if(!SSL_CTX_use_certificate_file(ctx, "TrustStore.pem", SSL_FILETYPE_PEM))
		{
			ERR_print_errors_fp(stdout);
			SSL_CTX_free(ctx);
			return 0;
		}
		if(!SSL_CTX_use_PrivateKey_file(ctx, "privatekey.key", SSL_FILETYPE_PEM))
		{
			ERR_print_errors_fp(stdout);
			SSL_CTX_free(ctx);
			return 0;
		}
		///

		if(result<0)
		{
			printf("\nBinding Error");
		}

		//connection
		listen(server_sockfd, 5);
		
		printf("server waiting\n");

		//accept connection
		ssl = SSL_new(ctx);
		client_len = sizeof(client_address);
		client_sockfd = accept(server_sockfd, (struct sockaddr *)&client_address, &client_len);
		printf("\nConnected\n");
		
		SSL_set_fd(ssl, client_sockfd);

		//handshake

		SSL_accept(ssl);
		printf("\nHandshake Done\n");
		
		result = SSL_write(ssl, &ch, sizeof(ch));
		if(result<0)
		{
			printf("\nwriting Error");
		}
		///////////////////////////////////////
		
		fp = fopen("bss_backup","wb");
		fwrite(&__bss_start,1,&_end - &__bss_start,fp);
		fclose(fp);
		
		fp = fopen("data_backup","wb");
		fwrite(&__data_start,1,&_edata - &__data_start,fp);
		fclose(fp);
		
		/*printf("Attempting to create BIO object... ");
		bio = BIO_new_ssl(ctx, 0);
		if(bio == NULL)
		{
			printf("Failed. Aborting.\n");
			ERR_print_errors_fp(stdout);
			SSL_CTX_free(ctx);
			return 0;
		}

		printf("\nAttempting to set up BIO for SSL...\n");
		BIO_get_ssl(bio, &ssl);
		SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
		printf("Waiting for incoming connection...\n");
		abio = BIO_new_accept("4422");
		BIO_set_accept_bios(abio, bio);

		if(BIO_do_accept(abio) <= 0)
		{
			ERR_print_errors_fp(stdout);
			SSL_CTX_free(ctx);
			BIO_free_all(bio);
			BIO_free_all(abio);
			return;
		}

		if(BIO_do_accept(abio) <= 0)
		{
			ERR_print_errors_fp(stdout);
			SSL_CTX_free(ctx);
			BIO_free_all(bio);
			BIO_free_all(abio);
			return;
		}
		out = BIO_pop(abio);
		
		if(BIO_do_handshake(out) <= 0)
		{
			printf("Handshake failed.\n");
			ERR_print_errors_fp(stdout);
			SSL_CTX_free(ctx);
			BIO_free_all(bio);
			BIO_free_all(abio);
			return;
		}
		printf("%ld\n",out);
		printf("Wrote: %d\n",BIO_puts(out, "Hello 123\n"));
		BIO_flush(out);
		
		fp = fopen("bss_backup","wb");
		fwrite(&__bss_start,1,&_end - &__bss_start,fp);
		fclose(fp);
		
		fp = fopen("data_backup","wb");
		fwrite(&__data_start,1,&_edata - &__data_start,fp);
		fclose(fp);
		
		ctx = NULL;
		out = NULL;
		ssl = NULL;*/
		
	}
	else
	{
		FILE * fp;
		
		//unnamed socket
		server_sockfd = socket(AF_INET, SOCK_STREAM, 0);

		//naming
		server_address.sin_family = AF_INET;
		server_address.sin_addr.s_addr = htonl(INADDR_ANY);
		server_address.sin_port = htons(9738);
		server_len = sizeof(server_address);
		result = bind(server_sockfd, (struct sockaddr *)&server_address, server_len);
		
		///
		printf("Attempting to create SSL context... ");
		ctx = SSL_CTX_new(SSLv23_server_method());
		
		if(ctx == NULL)
		{
			printf("Failed. Aborting.\n");
			return 0;
		}

		printf("\nLoading certificates...\n");
		SSL_CTX_set_default_passwd_cb(ctx, callback);
		if(!SSL_CTX_use_certificate_file(ctx, "TrustStore.pem", SSL_FILETYPE_PEM))
		{
			ERR_print_errors_fp(stdout);
			SSL_CTX_free(ctx);
			return 0;
		}
		if(!SSL_CTX_use_PrivateKey_file(ctx, "privatekey.key", SSL_FILETYPE_PEM))
		{
			ERR_print_errors_fp(stdout);
			SSL_CTX_free(ctx);
			return 0;
		}
		///

		if(result<0)
		{
			printf("\nBinding Error");
		}

		//connection
		listen(server_sockfd, 5);
		
		printf("server waiting\n");

		//accept connection
		ssl = SSL_new(ctx);
		
		/*SSL_load_error_strings();
		ERR_load_BIO_strings();
		ERR_load_SSL_strings();
		SSL_library_init();
		OpenSSL_add_all_algorithms();
		
		printf("Attempting to create SSL context... ");
		ctx = SSL_CTX_new(SSLv3_server_method());
		
		if(ctx == NULL)
		{
			printf("Failed. Aborting.\n");
			return 0;
		}

		printf("\nLoading certificates...\n");
		SSL_CTX_set_default_passwd_cb(ctx, callback);
		if(!SSL_CTX_use_certificate_file(ctx, "TrustStore.pem", SSL_FILETYPE_PEM))
		{
			ERR_print_errors_fp(stdout);
			SSL_CTX_free(ctx);
			return 0;
		}
		if(!SSL_CTX_use_PrivateKey_file(ctx, "privatekey.key", SSL_FILETYPE_PEM))
		{
			ERR_print_errors_fp(stdout);
			SSL_CTX_free(ctx);
			return 0;
		}

		printf("Attempting to create BIO object... ");
		bio = BIO_new_ssl(ctx, 0);
		if(bio == NULL)
		{
			printf("Failed. Aborting.\n");
			ERR_print_errors_fp(stdout);
			SSL_CTX_free(ctx);
			return 0;
		}

		printf("\nAttempting to set up BIO for SSL...\n");
		BIO_get_ssl(bio, &ssl);
		SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);*/
		
		/**
		 * Backup code - start
		 **/
		fp = fopen("/home/herat/Downloads/openssl-backup/shared","w");
		fprintf(fp,"1");
		fclose(fp);
		
		/**
		 * Backup code - end
		 **/
		
		/*printf("Waiting for incoming connection...\n");
		abio = BIO_new_accept("4422");
		BIO_set_accept_bios(abio, bio);
		
		if(BIO_do_accept(abio) <= 0)
		{
			ERR_print_errors_fp(stdout);
			SSL_CTX_free(ctx);
			BIO_free_all(bio);
			BIO_free_all(abio);
			return;
		}

		if(BIO_do_accept(abio) <= 0)
		{
			ERR_print_errors_fp(stdout);
			SSL_CTX_free(ctx);
			BIO_free_all(bio);
			BIO_free_all(abio);
			return;
		}
		out = BIO_pop(abio);
		
		if(BIO_do_handshake(out) <= 0)
		{
			printf("Handshake failed.\n");
			ERR_print_errors_fp(stdout);
			SSL_CTX_free(ctx);
			BIO_free_all(bio);
			BIO_free_all(abio);
			return;
		}*/
		
		fp = fopen("bss_backup","rb");
		fread(&__bss_start,1, &_end - &__bss_start,fp);
		fclose(fp);
		
		fp = fopen("data_backup","rb");
		fread(&__data_start,1, &_edata - &__data_start,fp);
		fclose(fp);
		
		ch = 'z';
		
		result = SSL_write(ssl, &ch, sizeof(ch));
		if(result<0)
		{
			printf("writing Error\n");
		}
	}	
}
