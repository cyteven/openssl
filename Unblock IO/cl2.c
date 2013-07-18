#include <stdio.h> 
#include <string.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <netdb.h> 
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

 
int main(int argc, char *argv[]) { 
int sockfd, portno, readfd, writefd, yes = 1; 
char buffer[1024]; 
struct hostent *server; 
struct sockaddr_in serv_addr/*, cli_addr*/;

//ssl initiation
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	ERR_load_SSL_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_METHOD *meth;
	meth = SSLv3_client_method();
	SSL_CTX *ctx;
	SSL* ssl;
	ctx = SSL_CTX_new(meth);    
	int result = SSL_CTX_load_verify_locations(ctx, "TrustStore1.pem", 0);
	printf("\nCA load result = %d\n", result);
	printf("\nSSL initialized\n");
 
 
    if(argc < 3) 
    {
    fprintf(stderr, "Ussage: %s IP Address port #", argv[0]);
    exit(EXIT_FAILURE);
    }
 
sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    if(sockfd < 0)  
    {
    fprintf(stderr, "SOCKET(-1) ---> %s.", strerror(errno));
    exit(EXIT_FAILURE);
    }
 
    if(sockfd == 0)  
    {
    fprintf(stderr, "SOCKET(0) ---> %s.", strerror(errno));
    exit(EXIT_FAILURE);
    }
 
int x = fcntl(sockfd, F_SETFL, O_NONBLOCK);
    if (x < 0)
    {
    printf("FCNTL(-1) ---> %s.\n", strerror(errno));
    /*close(sockfd);
    exit(EXIT_FAILURE);*/
    }
 
    if(x == 0)
    {
    printf("FCNTL(0) ---> %s.\n", strerror(errno));
    }
 
setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
 
bzero((char *) &serv_addr, sizeof(serv_addr)); 
server = gethostbyname(argv[1]); 
    if(server == NULL) 
    {
    fprintf(stderr, "No such host.");
    printf("SERVER(NULL) ---> %s", strerror(errno)); 
    exit(EXIT_FAILURE);
    }
 
portno = atoi(argv[2]); 
serv_addr.sin_family = AF_INET; 
memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length); 
serv_addr.sin_port = htons(portno);
 
    int connector = connect(sockfd, (const struct sockaddr *) &serv_addr, sizeof(serv_addr));
    if((connector < 0) && (!EINPROGRESS))
    { 
    fprintf(stderr, "CONNECT(-1) ---> %s.\n", strerror(errno));
    exit(EXIT_FAILURE);
    } 
        else
        { 
          fprintf(stdout, "Made a connection to %s\n", inet_ntoa(serv_addr.sin_addr)); 
        }
 
for( ; ; ) { 
int i = sizeof(buffer)-1; if(i > 0) bzero(buffer, sizeof(buffer)); 
    fprintf(stdout, "Message: "); 
    fgets(buffer, sizeof(buffer), stdin); 
    
    //ssl-ing the connection
   ssl = SSL_new(ctx);
   BIO *sbio;
   sbio = BIO_new(BIO_s_socket());
   BIO_set_fd(sbio, sockfd, BIO_CLOSE);
   SSL_set_bio(ssl, sbio, sbio);
   printf("Before SSL_connect: %d\n", result);
   result = SSL_connect(ssl);
   printf("SSL_connect: %d\n", result);
	
   /*if(SSL_get_peer_certificate(ssl)!=NULL)
   {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

		int result_long = SSL_get_verify_result(ssl);
		printf("\nCertificate Check Result: %d", result_long);
		if (SSL_get_verify_result(ssl) != X509_V_OK)
		{
			printf("\nCertiticate Verification Failed\n");
			return 0;
		}
		else
		{
			printf("\nCertiticate Verification Succeeded");
		}
	}*/
     
writefd = write(sockfd, buffer, strlen(buffer)-1);
    if(writefd > 0)
    {
    printf("Waiting for %s\n", inet_ntoa(serv_addr.sin_addr));
    }
        else
        {
            if(writefd < 0)
            { 
            fprintf(stderr, "WRITE(c) ---> %s.\n", strerror(errno));
            printf("errno = %d.\n", errno);
            exit(EXIT_FAILURE);
            }
         
            if(writefd == 0)
            {
            printf("WRITE(0). ---> %s.\n", strerror(errno));
            exit(EXIT_FAILURE);
            }
        }
 
 
//i = sizeof(buffer); if(i > 0) bzero(buffer, sizeof(buffer)-1); 
if((readfd <= 0) && (readfd == EAGAIN))
{
readfd = read(sockfd, buffer, sizeof(buffer));  
 
    /*if(readfd < 0) 
    { 
    fprintf(stderr, "Error reading message from %s\n", inet_ntoa(cli_addr.sin_addr)); 
    printf("READ(-1) ---> %s.\n", strerror(errno));
    exit(EXIT_FAILURE);
    } 
     
    //Test to see if the buffer is blank. Uncomment to test.
    if(readfd == 0)
    {
    printf("READ(0) ---> %s. Null buffer.\n", strerror(errno));
    exit(EXIT_FAILURE);
    }*/
         
    //else if((readfd == EAGAIN) && (readfd != EAGAIN))
    //{
    //fprintf(stdout, "%s", buffer);
    //}
 
}
        else
        {
        fprintf(stdout, "%s", buffer);
        }
 
}
 
close(sockfd);
 
return 0;
}
