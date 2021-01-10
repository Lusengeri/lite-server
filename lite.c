#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>

#define BACKLOG 1024
#define LINE_MAX 1024

int openlistenfd(char*);
void service_request(int);
void process_request_headers(FILE*);

int main(int argc, char *argv[])
{
	if (argc != 2){
		fprintf(stderr, "usage: %s <port>\n", argv[0]);
		exit(1);
	}

	int connfd, listenfd;
	struct sockaddr_storage client_addr;
	socklen_t client_len;
	char client_hostname[LINE_MAX], client_port[LINE_MAX];
	listenfd = openlistenfd(argv[1]);
		
	if (listenfd == -1){
		fprintf(stderr, "error in %s at %s: %s\n", __FILE__, __LINE__, strerror(errno));	
		exit(1);
	}	

	while(1){
		client_len = sizeof(client_addr) ;
		
		connfd = accept(listenfd, (struct sockaddr*) &client_addr, &client_len); 

		if (connfd == -1){
			fprintf(stderr, "error in %s at %s: %s\n", __FILE__, __LINE__, strerror(errno));	
			exit(1);
		}

		getnameinfo((struct sockaddr*) &client_addr, client_len, client_hostname, LINE_MAX, client_port, LINE_MAX, 0);
		printf("Connected to %s, %s\n", client_hostname, client_port);
		service_request(connfd);
		close(connfd);
	}
	exit(0);
}

int openlistenfd(char *port)
{
	int listenfd, optval=1;
	struct addrinfo hints, *p, *result;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
	hints.ai_flags |= AI_NUMERICSERV;

	getaddrinfo(NULL, port, &hints, &result);	

	for (p = result; p; p = p->ai_next){
		if (listenfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol) < 0)
			continue;

		setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void*)&optval, sizeof(int));

		if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0)
			break;

		close(listenfd);
	}

	freeaddrinfo(result);
	
	if (!p)
		return -1;

	if (listen(listenfd, BACKLOG) < 0){
		close(listenfd);
		return -1;
	}
	
	return listenfd;
}

void service_request(int connfd)
{
	char method[LINE_MAX], uri[LINE_MAX], version[LINE_MAX];	
	FILE *conn = fdopen(connfd, "r");

	if (!conn){
		fprintf(stderr, "error in %s at %s: %s\n", __FILE__, __LINE__, strerror(errno));	
		exit(1);
	}

	char curr_line[LINE_MAX];

	if (fgets(curr_line, LINE_MAX, conn) != NULL){
		sscanf(curr_line, "%s %s %s", method, uri, version);
	}

	process_request_headers(conn);

	fclose(conn);
}

void process_request_headers(FILE *conn)
{
	char curr_line[LINE_MAX];

	while (fgets(curr_line, LINE_MAX, conn) != NULL){
		if (strcmp(curr_line, "\r\n") == 0)
			break;
	}	
}
