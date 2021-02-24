#include "logging.h" 

void log_message(struct logger *log, char *log_message, log_lev level)
{	
	if (log == NULL) {
		struct logger def = {DEFAULT_LOG_LEVEL, stderr};	
		log = &def;
	}

	if (level >= log->level)
		fprintf(log->handler, "%s\n", log_message);
	return;
}
