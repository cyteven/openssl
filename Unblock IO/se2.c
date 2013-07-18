#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h> 

#include <openssl/ssl.h>
#include <openssl/err.h>

 
int main(int argc, char *argv[]) {
/* master file descriptor list */
fd_set master;
/* temp file descriptor list for select() */
fd_set read_fds;
/* server & client address */
struct sockaddr_in serv_addr, cli_addr; 
struct timeval timeout;
/* maximum file descriptor number */
int fdmax;
/* listening socket descriptor */
int sockfd;
/* newly accept()ed socket descriptor */
int newsockfd;
/* buffer for client data */
char buf[1024];
int nbytes;
/* for setsockopt() SO_REUSEADDR, below */
int yes = 1;
socklen_t clilen;
int i, j;
/* clear the master and temp sets */
FD_ZERO(&master);
FD_ZERO(&read_fds);

//ssl initiation
   SSL_load_error_strings();
   ERR_load_BIO_strings();
   ERR_load_SSL_strings();
   SSL_library_init();
   OpenSSL_add_all_algorithms();
	
   SSL_METHOD *meth = SSLv3_server_method();
   SSL_CTX *ctx = SSL_CTX_new(meth);
   SSL_CTX_use_certificate_file(ctx, "TrustStore.pem", SSL_FILETYPE_PEM);
   SSL_CTX_use_PrivateKey_file(ctx, "privatekey.key", SSL_FILETYPE_PEM);

  
if(argc < 2) 
{
printf("USAGE: %s + <portno>\n", argv[0]);
exit(EXIT_FAILURE);
}
 
timeout.tv_sec = 300;
timeout.tv_usec = 0;
 
/* get the listener */
sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) 
    {
    printf("%s. SOCKET()", strerror(errno));
    exit(EXIT_FAILURE); 
    }
        else if(sockfd)
        {
            do
            {
              {
              printf("Waiting for a connection.\n");
              }         
            } while(!accept);
        }
 
        printf("Server-socket() is OK...\n");
 
    /*"address already in use" error message */
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0)
    {
    printf("SETSOCKOPT() ---> %s.\n", strerror(errno));
    exit(EXIT_FAILURE);
    }
 
    printf("Server-setsockopt() is OK...\n");
  
/* bind */
int portno = atoi(argv[1]);
 
serv_addr.sin_family = AF_INET;
serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
serv_addr.sin_port = htons(portno);
memset(&(serv_addr.sin_zero), '\0', 8);
 
int binder; 
binder = bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
 
    if(binder == -1)
    {
    printf("BIND() ---> %s.\n", strerror(errno));
    exit(EXIT_FAILURE);
    }
     
    printf("Server-bind() is OK...\n");
  
/* listen */
int listener = listen(sockfd, 10);
    if(listener < 0)
    {
    printf("LISTEN() ---> %s.\n", strerror(errno));
    exit(EXIT_FAILURE);
    }
 
    printf("Server-listen() is OK...\n");
  
/* add the listener to the master set */
FD_SET(sockfd, &master);
/* keep track of the biggest file descriptor */
fdmax = sockfd; /* so far, it's this one*/
 
/* Main loop */
for( ; ; ) 
{
/* copy it */
read_fds = master;
  
    int selector = select(fdmax+1, &read_fds, NULL, NULL, &timeout);
    if(selector < 0)
    {
    printf("SELECT(-1) ---> %s.\n", strerror(errno));
    exit(EXIT_FAILURE);
    }
 
    if(selector == 0)
    {
    printf("SELECT(0) ---> %s.\n", strerror(errno));
    exit(EXIT_FAILURE);
    }
 
     
    else
    {
    printf("Server-select() is OK...\n");
    printf("Waiting for data...\n");
    }
 
 
  
/*run through the existing connections looking for data to be read*/
for(i = 0; i <= fdmax; i++)
{//2nd for loop
        if(FD_ISSET(i, &read_fds))
        { /* we got one... */
 
            if(i == sockfd)
            {
            /* handle new connections */
            clilen = sizeof(cli_addr);
 
            if((newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen)) == -1)
            {
            printf("ACCEPT() ---> %s.\n", strerror(errno));
            exit(EXIT_FAILURE);
            }
                else
                {
                printf("Server-accept() is OK...\n");
                FD_SET(newsockfd, &master); /* add to master set */
 
                    if(newsockfd > fdmax)
                    {
                    /* keep track of the maximum */
                    fdmax = newsockfd;
                    }
 
                printf("%s: New connection from %s on socket %d\n", argv[0], inet_ntoa(cli_addr.sin_addr), newsockfd);
                SSL* ssl;
		   ssl = SSL_new(ctx);
		   SSL_set_fd(ssl, newsockfd);

		   SSL_accept(ssl);
		   printf("\nHandshake Done\n");
                }
        }
 
    else
    {
		
    /* handle data from a client */
        if((nbytes = recv(i, buf, sizeof(buf), 0)) <= 0)
        {
        /* got error or connection closed by client */
        if(nbytes == 0)
        /* connection closed */
        printf("%s: socket %d hung up\n", argv[0], i);
  
            else
            printf("RECV() ---> %s.\n", strerror(errno));
            /* close it... */
            close(i);
            /* remove from master set */
            FD_CLR(i, &master);
            }
 
                else
                {
                /* we got some data from a client*/
                    for(j = 0; j <= fdmax; j++)
                    {//3rd for loop
                        /* send to everyone! */
                        if(FD_ISSET(j, &master))
                        {
                        /* except the listener and ourselves */
                            if(j != sockfd && j != i)
                            {
                                if(send(j, buf, nbytes, 0) == -1)
                                {
                                printf("SEND() ---> %s.\n", strerror(errno));
                                exit(EXIT_FAILURE);
                                }   
                            }
                        }   
                    }//3rd for loop
                }
        }
    }
}//2nd for loop
}//Main loop
return 0;
}
