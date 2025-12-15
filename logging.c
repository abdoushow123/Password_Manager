//Filename : logging.c
#include "logging.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>

static FILE *log_file = NULL;
static bool terminal_output = true;

static void open_log_file() {
    if (!log_file) {
        log_file = fopen("app.log", "a");
        if (log_file == NULL) {
            perror("Failed to open log file");
        }
    }
}

static void close_log_file() {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}

static void log_to_file(const char *level, const char *format, va_list args) {
    open_log_file();
    if (!log_file) return;

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    if (!t) return;

    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", t);

    fprintf(log_file, "[%s] [%s] ", timebuf, level);
    vfprintf(log_file, format, args);
    fprintf(log_file, "\n");
    fflush(log_file);
}

static void log_to_terminal(const char *level, const char *format, va_list args) {
    if (!terminal_output) return;
    
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    if (!t) return;

    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", t);
    
    if (strcmp(level, "MESSAGE") == 0) {
        vprintf(format, args);
        printf("\n");
    } else {
        printf("[%s] [%s] ", timebuf, level);
        vprintf(format, args);
        printf("\n");
    }
    fflush(stdout);
}

void log_message_error(const char *format, ...) {
    va_list args1, args2;
    va_start(args1, format);
    va_copy(args2, args1);
    
    log_to_file("ERROR", format, args1);
    log_to_terminal("ERROR", format, args2);
    
    va_end(args1);
    va_end(args2);
}

void log_message_info(const char *format, ...) {
    va_list args1, args2;
    va_start(args1, format);
    va_copy(args2, args1);
    
    log_to_file("INFO", format, args1);
    log_to_terminal("INFO", format, args2);
    
    va_end(args1);
    va_end(args2);
}

void log_message(const char *format, ...) {
    va_list args1, args2;
    va_start(args1, format);
    va_copy(args2, args1);
    
    log_to_file("INFO", format, args1);
    log_to_terminal("MESSAGE", format, args2);
    
    va_end(args1);
    va_end(args2);
}

void set_terminal_output(bool enable) {
    terminal_output = enable;
}

__attribute__((destructor))
static void on_exit() {
    close_log_file();
}
