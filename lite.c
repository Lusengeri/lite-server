#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <netdb.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "logging.h"

#define BACKLOG 1024					// The maximum number of unserviced connection requests that may be queued
#define MAX_LINE_LEN 1024

extern char **environ;

int get_listen_sock(char*);
void service_request(SSL*);
void serve_static(SSL*, char *);
void serve_dynamic(SSL*, char *);
void response_400(SSL *ssl);
void response_404(SSL *ssl);
const char *get_content_type(const char*);

int main(int argc, char *argv[])
{
	/* The web-server software takes the port on which to listen for connections as the sole command line argument */
	if (argc != 2) {
		//fprintf(stderr, "usage: %s <port>\n", argv[0]);
		struct logger info_logger = { INFO, stdout};
		log_message(&info_logger, "usage: %s <port>", INFO);
		exit(EXIT_FAILURE);
	}

	/* We then create the socket that listens on the supplied port number */
	int listen_sock = get_listen_sock(argv[1]);
		
	/* If creation of the listening socket fails, then the retured descriptor value is -1 in which case we terminate the program */
	if (listen_sock == -1) {
		//fprintf(stderr, "error: Creation of listening socket failed\n");	
		log_message(NULL, "error: Creation of listening socket failed", ERROR);
		exit(EXIT_FAILURE);
	}

	printf("Now listening on port: %s\n", argv[1]);
	
	/* We initialize the SSL library (which implements the Transport Layer Security (TLS) protocol */
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	while (1) {
		/* We create the data structure to store the address of the client connecting to the server */
		struct sockaddr_storage client_addr;
		socklen_t client_len = sizeof(client_addr);

		/* We accept connections on our listening socket */
		int client_sock = accept(listen_sock, (struct sockaddr*) &client_addr, &client_len); 

		/* If accept() fails (i.e. returns -1) for whatever reason we print an error message and terminate the program */
		if (client_sock == -1) {
			//fprintf(stderr, "error: accept() failed: %s\n", strerror(errno));	
			log_message(NULL, "error: accept() failed", ERROR);
			exit(EXIT_FAILURE);
		}

		/* We then print the details of the client whose connection request we have accepted */
		char client_hostname[MAX_LINE_LEN], client_port[MAX_LINE_LEN];
		getnameinfo((struct sockaddr*) &client_addr, client_len, client_hostname, MAX_LINE_LEN, client_port, MAX_LINE_LEN, 0);
		printf("Connected to %s, %s\n", client_hostname, client_port);

		/* Once connected to a client we try to establish a secure connection before responding to any request */
		/* We create an SSL context which functions as a sort of factory for creating SSL objects */
		SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
		if (!ctx) {
			//fprintf(stderr, "error: SSL_CTX_new() failed.\n");
			log_message(NULL, "error: SSL_CTL_new() failed", ERROR);
			exit(EXIT_FAILURE);
		}

		/* We set the newly created context to use our self-signed certificate */
		if (!SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) || !SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM)) {
			//fprintf(stderr, "error: SSL_CTX_use_certificate_file() failed.\n");
			log_message(NULL, "error: SSL_CTL_use_certificate_file() failed", ERROR);
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE); 
		}

		/*We then create a new SSL object*/
		SSL *ssl = SSL_new(ctx);
		if (!ssl) {
			//fprintf(stderr, "error: SSL_new() failed\n");
			log_message(NULL, "error: SSL_new() failed", ERROR);
			exit(EXIT_FAILURE);
		}

		/*And then link the newly created SSL object to use the socket of the accepted connection */
		SSL_set_fd(ssl, client_sock);

		// We can now accept connections on the SSL object 
		if (SSL_accept(ssl) <= 0) {
			//fprintf(stderr, "SSL_accept() failed.\n");
			log_message(NULL, "SSL_accept() failed", ERROR);
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE);
		}

		printf("Secure connection using %s\n", SSL_get_cipher(ssl));

		// We then service client requests on the encrypted communication channel 
		service_request(ssl);

		// All resources are freed once the request is serviced
		SSL_shutdown(ssl);
		close(client_sock);
		SSL_free(ssl);
	}
	exit(EXIT_SUCCESS);
}

// get_listen_sock() creates the socket that shall listen for incoming connections and binds it to the specified port number
int get_listen_sock(char *port)
{
	int listen_sock, optval=1;
	struct addrinfo hints, *p, *address_list;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_socktype = SOCK_STREAM;				// TCP sockets to be used
	hints.ai_family = AF_INET;					// IPV4 supported
	hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;			// Accept requests on any of available IP addresses 
	hints.ai_flags |= AI_NUMERICSERV;				// Web service specified as a port no

	int gai_err;
	if ((gai_err = getaddrinfo(NULL, port, &hints, &address_list)) != 0) {
		char err_buf[1024];
		sprintf(err_buf, "getaddrinfo() failed: %s", gai_strerror(gai_err));
		log_message(NULL, err_buf, CRITICAL);
		exit(EXIT_FAILURE);
	}

	for (p = address_list; p; p = p->ai_next) {
		if ((listen_sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0)
			continue;

		// We ensure that the listening socket is reusable immediately after the program terminates 
		setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const void*)&optval, sizeof(int));
		
		if ((bind(listen_sock, p->ai_addr, p->ai_addrlen)) == 0)
			break;

		close(listen_sock);
	}

	freeaddrinfo(address_list);
	
	//If the entire address list is exhausted without a successful bind, p shall have a null value
	if (!p)
		return -1;

	//The socket is made into a listening socket
	if ((listen(listen_sock, BACKLOG)) < 0) {
		close(listen_sock);
		return -1;
	}
	return listen_sock;
}

void service_request(SSL *ssl)
{
	char inp_buffer[4096];
	SSL_read(ssl, inp_buffer, 4096); 
	char *str = strtok(inp_buffer, "\r\n");
	char method[64], uri[1024], version[64];
	sscanf(str, "%s %s %s", method, uri, version);

	if (strcmp(method, "GET") == 0) {
		if (strcmp(uri, "/") == 0) {
			serve_static(ssl, "sample_site/""index.html");
		} else if (strncmp(uri, "/cgi-bin", 8) == 0) {
			//printf("CGI script operation requested\n");	
			serve_dynamic(ssl, uri);
		} else {
			char url[1024];
			strcat(url, "sample_site/");
			strcat(url, strtok(uri, "/"));
			serve_static(ssl, url);
		}
	} else {
		response_400(ssl);	
	}
}

void serve_static(SSL *ssl, char *resource_name)
{
	FILE *resource = fopen(resource_name, "r");	

	if (resource == NULL) {
		fprintf(stderr, "fopen(%s) failed\n", resource_name);
		response_404(ssl);
		return;
	}

	char string_buffer[1024];

	sprintf(string_buffer, "HTTP/1.0 200 0K\r\n");
	SSL_write(ssl, string_buffer, strlen(string_buffer));

	sprintf(string_buffer, "Connection: close\r\n");
	SSL_write(ssl, string_buffer, strlen(string_buffer));

	int content_len = 0;

	while (fgetc(resource) != EOF) {
		content_len += 1;
	}
	rewind(resource);

	sprintf(string_buffer, "Content-Length: %d\r\n", content_len);
	SSL_write(ssl, string_buffer, strlen(string_buffer));

	const char *ct = get_content_type(resource_name);
	sprintf(string_buffer, "Content-Type: %s\r\n", ct);
	SSL_write(ssl, string_buffer, strlen(string_buffer));

	sprintf(string_buffer, "Server: lite-server\r\n");
	SSL_write(ssl, string_buffer, strlen(string_buffer));

	sprintf(string_buffer, "\r\n");
	SSL_write(ssl, string_buffer, strlen(string_buffer));

	int read_items;

	while ((read_items = fread(string_buffer, 1, 1024, resource)) != 0) {
		SSL_write(ssl, string_buffer, read_items);
	}
	
	fclose(resource);
}

void serve_dynamic(SSL *ssl, char *uri)
{
	char *script_name = strtok(uri, "?");
	script_name++;
	//printf("Script_name: %s\n", script_name);
	char *cgi_args = strtok(NULL, "?");
	//printf("CGI args: %s\n", cgi_args);
	
	char buf[4096], *empty_list[] = {NULL};

	sprintf(buf, "HTTP/1.0 200 OK\r\n"); 
	SSL_write(ssl, buf, strlen(buf));

	sprintf(buf, "Server: lite-server\r\n"); 
	SSL_write(ssl, buf, strlen(buf));

	int fail = 0;
	//printf("About to fork!\n");

	int write_back = fileno(tmpfile());

	if (fork() == 0) {
		//printf("After fork\n");
		setenv("QUERY_STRING", cgi_args, 1);
		dup2(write_back, STDOUT_FILENO);
		fail = execve(script_name, empty_list, environ);
	}

	if (fail == -1)
		fprintf(stderr, "execve() failed: %s\n", strerror(errno));

	int status;
	wait(&status);

	char outp_buf[4096];
	//printf("Reading output of CGI script ...\n");

	lseek(write_back, 0, SEEK_SET);
	read(write_back, outp_buf, 4096);
	SSL_write(ssl, outp_buf, strlen(outp_buf));
}

void response_400(SSL *ssl)
{
	const char *c400 = "HTTP/1.1 400 Bad Request\r\n" "Connection: close\r\n" "Content-Length: 11\r\n\r\nBad Request";
	SSL_write(ssl, c400, strlen(c400));
}

void response_404(SSL *ssl)
{
	const char *c404 = "HTTP/1.1 400 Not Found\r\n" "Connection: close\r\n" "Content-Length: 9\r\n\r\nNot Found";
	SSL_write(ssl, c404, strlen(c404));
}

const char *get_content_type(const char* path)
{
	const char *last_dot = strchr(path, '.');

	if (last_dot) {
		if (strcmp(last_dot, ".css") == 0) return "text/css";
		if (strcmp(last_dot, ".csv") == 0) return "text/csv";
		if (strcmp(last_dot, ".gif") == 0) return "image/gif";
		if (strcmp(last_dot, ".htm") == 0) return "text/html";
		if (strcmp(last_dot, ".html") == 0) return "text/html";
		if (strcmp(last_dot, ".ico") == 0) return "image/x-icon";
		if (strcmp(last_dot, ".jpeg") == 0) return "image/jpeg";
		if (strcmp(last_dot, ".jpg") == 0) return "image/jpeg";
		if (strcmp(last_dot, ".js") == 0) return "application/javascript";
		if (strcmp(last_dot, ".json") == 0) return "application/json";
		if (strcmp(last_dot, ".png") == 0) return "image/png";
		if (strcmp(last_dot, ".pdf") == 0) return "application/pdf";
		if (strcmp(last_dot, ".svg") == 0) return "image/svg";
		if (strcmp(last_dot, ".txt") == 0) return "text/plain";
	}
	return "application/octet-stream";
}
