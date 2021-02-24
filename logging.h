#include <stdio.h>

typedef enum {NOTSET, DEBUG, INFO, WARNING, ERROR, CRITICAL} log_lev;

#define DEFAULT_LOG_LEVEL WARNING

struct logger {
	log_lev level;
	FILE *handler;
};

void log_message(struct logger *log, char *log_message, log_lev level);
