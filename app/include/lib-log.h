#ifndef _LIB_LOG_H
#define _LIB_LOG_H

#include <time.h>
#include <pthread.h>
#include "ndpi_api.h"
#include "stdarg.h"
#include "stdio.h"

#include "lib-zmq.h"
#include "lib-string.h"

// Macros
#define LOG_LEVEL_ERROR       1
#define LOG_LEVEL_WARNING     2
#define LOG_LEVEL_INFO        3
#define LOG_LEVEL_DEBUG       4

#define LOGGER_TYPE_FILE     0
#define LOGGER_TYPE_STDOUT   1
#define LOGGER_TYPE_ZMQ     2

// Structs
typedef struct log_t {
    int level;
    time_t timestamp;
    string_t tag;
    string_t message;
} log_t;

struct logger {
    int type;
    FILE* output_file;
    struct lzmq_interface* zmq_int;
};

// Functions
uint8_t logger_init(struct logger* logger, int type, char* addr);
void logger_delete(struct logger* logger);
uint8_t logger_log_stdout(log_t* log);
uint8_t logger_log_file(struct logger* logger, log_t* log);
uint8_t logger_log(struct logger* logger, log_t* log);
uint8_t logger_log_raw(
    struct logger* logger,
    int level,
    char* tag,
    char* __restrict__ pattern, ...
);

/* ***************************************************** */

log_t log_create(int level, char* tag, char* message);
void log_delete(log_t* log);
string_t log_generate_string(log_t* log);
const char* log_level_to_string(int level);

#endif