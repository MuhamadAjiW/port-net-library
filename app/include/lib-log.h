#ifndef _LIB_LOG_H
#define _LIB_LOG_H

#include <time.h>
#include <pthread.h>
#include "lib-string.h"
#include "stdio.h"

// Macros
#define LOG_LEVEL_ERROR       1
#define LOG_LEVEL_WARNING     2
#define LOG_LEVEL_INFO        3
#define LOG_LEVEL_DEBUG       4

#define LOGGER_TYPE_FILE     0
#define LOGGER_TYPE_STDOUT   1

// Structs
struct log_t {
    int level;
    time_t timestamp;
    string_t tag;
    string_t message;
};

struct logger_t {
    FILE* output_file;
    int type;
};

// Functions
uint8_t logger_init(struct logger_t* logger, int type, char* path);
void logger_delete(struct logger_t* logger);
uint8_t logger_log_stdout(struct log_t* log);
uint8_t logger_log_file(struct logger_t* logger, struct log_t* log);
uint8_t logger_log(struct logger_t* logger, struct log_t* log);
uint8_t logger_log_raw(
    struct logger_t* logger,
    int level,
    char* tag,
    char* message
);

/* ***************************************************** */

struct log_t log_create(int level, char* tag, char* message);
void log_delete(struct log_t* log);
string_t log_generate_string(struct log_t* log);
const char* log_level_to_string(int level);

#endif