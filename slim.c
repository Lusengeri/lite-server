#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#define BACKLOG 1024

int openlistenfd(char *port)
{
	int listenfd, optval=1, err_code;
	struct addrinfo hints, *p, **result;

	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
	hints.ai_flags |= AI_NUMERICSERV;

	if (err_code = getaddrinfo(NULL, port, &hints, result) != 0){	
		fprintf(stderr, "%s", gai_strerror(err_code));
		exit(1);
	}

	for (p = *result; p; p = p->ai_next){
		if (listenfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol) < 0)
			continue;

		setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void*)&optval, sizeof(int));

		if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0)
			break;

		close(listenfd);
	}

	freeaddrinfo(*result);
	
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

	int connfd = openlistenfd(argv[1]);	
	exit(0);
}
