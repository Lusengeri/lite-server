#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAXLINE 1024

int main(int argc, char *argv[])
{
	char *buf, *p;
	char arg1[MAXLINE], arg2[MAXLINE], content[MAXLINE];	
	int n1 = 0, n2 = 0;

	/*Extract the two arguments */

	if ((buf = getenv("QUERY_STRING")) != NULL) {
		p = strchr(buf, '&');
		*p = '\0';
		strcpy(arg1, buf);
		strcpy(arg2, p+1);
		n1 = atoi(arg1);
		n2 = atoi(arg2);
	}

	sprintf(content, "QUERY_STRING=%s", buf);
	sprintf(content, "Welcome to add.com ");
	sprintf(content, "%s THE Internet addition portal.\r\n<p>", content);
	sprintf(content, "%sThe answer is: %d + %d = %d\r\n<p>", content, n1, n2, n1+n2);
	sprintf(content, "%sThanks for visiting!\r\n", content);

	/*Generate the HTTP response*/
	
	printf("Connection: close \r\n");
	printf("Content-Length: %d\r\n", (int)strlen(content));
	printf("Content-Type: text/html\r\n\r\n");
	printf("%s", content);
	fflush(stdout);
	
	exit(0);
}
