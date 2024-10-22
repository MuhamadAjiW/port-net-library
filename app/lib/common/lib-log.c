#include "../../include/lib-log.h"

uint8_t logger_init(struct logger_t* logger, int type, char* path) {
    switch (type)
    {
    case LOGGER_TYPE_STDOUT:
        return 1;
    case LOGGER_TYPE_FILE:
        logger->output_file = fopen(path, "w+");
        if (logger->output_file == NULL) return 0;
        return 1;

    default:
        return 0;
    }
}

void logger_delete(struct logger_t* logger) {
    fclose(logger->output_file);
}

uint8_t logger_log_stdout(struct log_t* log) {
    string_t str = log_generate_string(log);
    printf(str.content);
    str_delete(&str);

    return 1;
}

uint8_t logger_log_file(struct logger_t* logger, struct log_t* log) {
    if (logger->output_file == NULL) return 0;
    string_t str = log_generate_string(log);

    fprintf(logger->output_file, str.content);
    fflush(logger->output_file);

    str_delete(&str);
    return 1;
}

uint8_t logger_log(struct logger_t* logger, struct log_t* log) {
    switch (logger->type) {
    case LOGGER_TYPE_FILE:
        return logger_log_file(logger, log);
    case LOGGER_TYPE_STDOUT:
        return logger_log_stdout(log);

    default:
        return 0;
    }
}

uint8_t logger_log_raw(
    struct logger_t* logger,
    int level,
    char* tag,
    char* __restrict__ pattern, ...
) {
    va_list args;
    va_start(args, pattern);
    int len = vsnprintf(NULL, 0, pattern, args) + 1;
    va_end(args);

    char* message = malloc(len);
    if (message == NULL) return 0;

    va_start(args, pattern);
    vsnprintf(message, len, pattern, args);
    va_end(args);

    struct log_t log = log_create(level, tag, message);
    int retcode = logger_log(logger, &log);

    log_delete(&log);
    free(message);

    return retcode;
}

/* ***************************************************** */

struct log_t log_create(int level, char* tag, char* message) {
    struct log_t log;

    log.message = str_new(message);
    log.tag = str_new(tag);
    log.level = level;
    log.timestamp = time(NULL);

    return log;
}

void log_delete(struct log_t* log) {
    str_delete(&(log->message));
    str_delete(&(log->tag));
}

string_t log_generate_string(struct log_t* log) {
    string_t output_string;
    struct tm* t;
    char timestamp[20];
    t = localtime(&log->timestamp);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

    output_string = str_format("%s [%s] [%s]: %s\n",
        timestamp,
        log_level_to_string(log->level),
        log->tag.content,
        log->message.content
    );

    return output_string;
}

const char* log_level_to_string(int level) {
    switch (level)
    {
    case LOG_LEVEL_ERROR:
        return "ERROR";
    case LOG_LEVEL_WARNING:
        return "WARNING";
    case LOG_LEVEL_INFO:
        return "INFO";
    case LOG_LEVEL_DEBUG:
        return "DEBUG";

    default:
        return "";
        break;
    }
}