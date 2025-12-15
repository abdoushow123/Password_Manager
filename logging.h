
#ifndef LOGGING_H
#define LOGGING_H

#include <stdbool.h>

void log_message_error(const char *format, ...);
void log_message_info(const char *format, ...);
void log_message(const char *format, ...);
void set_terminal_output(bool enable);

#endif
