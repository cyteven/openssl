#include <stdio.h>
#include <string.h>

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <openssl/rsa.h>

extern char  __data_start, __bss_start,_edata,_end; 
SSL_CTX *ctx;
SSL *ssl;
BIO *bio, *abio, *out, *sbio;
int p;
char r[1024];

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
    /*printf("%d",argc);
    
    printf("    Data Start  %10p\n", &__data_start);
    printf("    Data End  %10p\n", &_edata);
    printf("    BSS Start %10p\n", &__bss_start);
    printf("    BSS End %10p\n", &_end);*/
    
    printf("Secure Programming with the OpenSSL API, Part 4:\n");
    printf("Serving it up in a secure manner\n\n");
    
    if(argc == 1)
    {
		FILE * fp;
		SSL_load_error_strings();
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
		ssl = NULL;
	//}
	//else
	//{
	//	FILE * fp;
		
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
		
		printf("%ld\n",out);
		
		BIO_puts(out, "Hello123\n");
		BIO_flush(out);
		
		BIO_free_all(out);
		BIO_free_all(bio);
		BIO_free_all(abio);

		SSL_CTX_free(ctx);
	}	
}
