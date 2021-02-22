#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BACKLOG 1024
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
	/*The web-server takes the port on which to listen for connections as a command line argument*/
	if (argc != 2){
		fprintf(stderr, "usage: %s <port>\n", argv[0]);
		exit(1);
	}

	/*We then create the socket that listens on the supplied port number*/
	int listen_sock = get_listen_sock(argv[1]);
		
	/*If creation of the listening socket fails, then the associated file descriptor is negative, in which case we terminate the program*/
	if (listen_sock == -1){
		fprintf(stderr, "error in %s at %d: %s\n", __FILE__, __LINE__, strerror(errno));	
		exit(1);
	}

	printf("Now listening on port: %s\n", argv[1]);
	
	/*We initialize the SSL library*/
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	while(1){
		/*We create the data structure to store the address of the client connecting to the server*/
		struct sockaddr_storage client_addr;
		socklen_t client_len = sizeof(client_addr) ;

		/*We accept connections on our listening socket*/
		int client_sock = accept(listen_sock, (struct sockaddr*) &client_addr, &client_len); 

		/*If accept() fails (i.e. returns -1) for whatever reason we print an error message and terminate the program*/
		if (client_sock == -1){
			fprintf(stderr, "error in %s at %s: %s\n", __FILE__, __LINE__, strerror(errno));	
			exit(1);
		}

		/*We then print the details of the client whose connection request we have accepted*/
		char client_hostname[MAX_LINE_LEN], client_port[MAX_LINE_LEN];
		getnameinfo((struct sockaddr*) &client_addr, client_len, client_hostname, MAX_LINE_LEN, client_port, MAX_LINE_LEN, 0);
		printf("Connected to %s, %s\n", client_hostname, client_port);
		
		/* Once connected to a client we try to establish a secure connection before responding to any request
		 * We create an SSL context which functions as a sort of factory for creating SSL objects*/

		SSL_CTX *ctxt = SSL_CTX_new(TLS_server_method());
		if (!ctxt) {
			fprintf(stderr, "SSL_CTX_new() failed.\n");
			return 1;
		}

		/*We set the newly created context to use our self-signed certificate*/
		if (!SSL_CTX_use_certificate_file(ctxt, "cert.pem", SSL_FILETYPE_PEM) || !SSL_CTX_use_PrivateKey_file(ctxt, "key.pem", SSL_FILETYPE_PEM)) {
			fprintf(stderr, "SSL_CTX_use_certificate_file() failed.\n");
			ERR_print_errors_fp(stderr);
			return 1; }

		/*We then create a new SSL object*/
		SSL *ssl = SSL_new(ctxt);
		if (!ssl) {
			fprintf(stderr, "SSL_new() failed\n");
			return 1;
		}

		/*And then link the SSL object to our open socket*/
		SSL_set_fd(ssl, client_sock);
		if (SSL_accept(ssl) <= 0) {
			fprintf(stderr, "SSL_accept() failed.\n");
			ERR_print_errors_fp(stderr);
			return 1;
		}

		printf("SSL connection using %s\n", SSL_get_cipher(ssl));

		service_request(ssl);
		/*Free resources */
		SSL_shutdown(ssl);
		close(client_sock);
		SSL_free(ssl);
	}
	exit(0);
}

int get_listen_sock(char *port)
{
	int listen_sock, optval=1;
	struct addrinfo hints, *p, *result;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;
	hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
	hints.ai_flags |= AI_NUMERICSERV;

	getaddrinfo(NULL, port, &hints, &result);	

	for (p = result; p; p = p->ai_next){
		if ((listen_sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0)
			continue;

		setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const void*)&optval, sizeof(int));

		if ((bind(listen_sock, p->ai_addr, p->ai_addrlen)) == 0)
			break;

		close(listen_sock);
	}

	freeaddrinfo(result);
	
	if (!p)
		return -1;

	if ((listen(listen_sock, BACKLOG)) < 0){
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
			printf("CGI script resource\n");	
			serve_dynamic(ssl, uri);
			//response_400(ssl);	
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

	char *buf[1024];
	int read_items;

	while ((read_items = fread(buf, 1, 1024, resource)) != 0) {
		SSL_write(ssl, buf, read_items);
	}
	
	fclose(resource);
}

void serve_dynamic(SSL *ssl, char *uri)
{
	char *script_name = strtok(uri, "?");
	script_name++;
	printf("Script_name: %s\n", script_name);
	char *cgi_args = strtok(NULL, "?");
	printf("CGI args: %s\n", cgi_args);
	
	int write_back = open("write_back", O_RDWR | O_CREAT | O_TRUNC, 0644);
	char buf[4096], *empty_list[] = {NULL};

	sprintf(buf, "HTTP/1.0 200 OK\r\n"); 
	SSL_write(ssl, buf, strlen(buf));

	sprintf(buf, "Server: lite-server\r\n"); 
	SSL_write(ssl, buf, strlen(buf));

	int fail = 0;
	printf("About to fork!\n");

	if (fork() == 0) {
		printf("After fork\n");
		setenv("QUERY_STRING", cgi_args, 1);
		dup2(write_back, STDOUT_FILENO);
		fail = execve(script_name, empty_list, environ);
	}

	if (fail == -1)
		fprintf(stderr, "execve() failed: %s\n", strerror(errno));

	int status;
	wait(&status);

	char outp_buf[4096];
	printf("Reading output of CGI script ...\n");

	lseek(write_back, 0, SEEK_SET);
	read(write_back, outp_buf, 4096);
	SSL_write(ssl, outp_buf, strlen(outp_buf));

	close(write_back);
	system("rm write_back");
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
