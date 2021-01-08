#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>

#define BACKLOG 1024

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

int main(int argc, char *argv[])
{
	if (argc != 2){
		fprintf(stderr, "usage: %s <port>\n", argv[0]);
		exit(0);
	}

	int listenfd = openlistenfd(argv[1]);	
	struct sockaddr_storage client_addr;
	int client_len;
	char inp_buf[1024];
	char client_name[1024], client_port[1024];

	while(1){
		client_len = sizeof(struct sockaddr_storage);
		int connfd = accept(listenfd, (struct sockaddr*) &client_addr, &client_len);
		getnameinfo((struct sockaddr*) &client_addr, client_len, client_name, 1024, client_port, 1024, 0);
		printf("Connected to %s, %s\n", client_name, client_port);
		read(connfd, inp_buf, 1024);
		printf("%s\n", inp_buf);
		close(connfd);
	}
	exit(0);
}
