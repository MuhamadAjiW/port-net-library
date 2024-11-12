#include "../../include/lib-log.h"

uint8_t logger_init(struct logger* logger, int type, char* addr) {
    switch (type)
    {
    case LOGGER_TYPE_STDOUT:
        logger->type = type;
        return 1;

    case LOGGER_TYPE_FILE:
        logger->output_file = fopen(addr, "w+");
        if (logger->output_file != NULL) {
            logger->type = type;
            return 1;
        }
        break;

    case LOGGER_TYPE_ZMQ:
        logger->zmq_int = ndpi_malloc(sizeof(struct lzmq_interface));

        if (lzmq_int_init(logger->zmq_int, addr, ZMQ_PUB)) {
            logger->type = type;
            return 1;
        }

        ndpi_free(logger->zmq_int);
        break;
    }

    logger->type = 0;
    return 0;
}

void logger_delete(struct logger* logger) {
    switch (logger->type)
    {
    case LOGGER_TYPE_STDOUT:
        return;
    case LOGGER_TYPE_FILE:
        fclose(logger->output_file);
        return;
    case LOGGER_TYPE_ZMQ:
        lzmq_int_cleanup(logger->zmq_int);
        ndpi_free(logger->zmq_int);
        return;

    default:
        break;
    }
}

uint8_t logger_log_stdout(log_t* log) {
    string_t str = log_generate_string(log);
    printf(str.content);
    str_delete(&str);

    return 1;
}

uint8_t logger_log_file(struct logger* logger, log_t* log) {
    if (logger->output_file == NULL) return 0;
    string_t str = log_generate_string(log);

    fprintf(logger->output_file, str.content);
    fflush(logger->output_file);

    str_delete(&str);
    return 1;
}

uint8_t logger_log_zmq(struct logger* logger, log_t* log) {
    if (!lzmq_int_initialized(logger->zmq_int)) return 0;

    string_t str = log_generate_string(log);

    zmq_send(logger->zmq_int->socket, str.content, str.len, 0);

    str_delete(&str);
    return 1;
}

uint8_t logger_log(struct logger* logger, log_t* log) {
    switch (logger->type) {
    case LOGGER_TYPE_FILE:
        return logger_log_file(logger, log);
    case LOGGER_TYPE_STDOUT:
        return logger_log_stdout(log);
    case LOGGER_TYPE_ZMQ:
        return logger_log_zmq(logger, log);

    default:
        return 0;
    }
}

uint8_t logger_log_raw(
    struct logger* logger,
    int level,
    char* tag,
    char* __restrict__ pattern, ...
) {
    va_list args;
    va_start(args, pattern);
    int len = vsnprintf(NULL, 0, pattern, args) + 1;
    va_end(args);

    char* message = ndpi_malloc(len);
    if (message == NULL) return 0;

    va_start(args, pattern);
    vsnprintf(message, len, pattern, args);
    va_end(args);

    log_t log = log_create(level, tag, message);
    int retcode = logger_log(logger, &log);

    log_delete(&log);
    ndpi_free(message);

    return retcode;
}

/* ***************************************************** */

log_t log_create(int level, char* tag, char* message) {
    log_t log;

    log.message = str_new(message);
    log.tag = str_new(tag);
    log.level = level;
    log.timestamp = time(NULL);

    return log;
}

void log_delete(log_t* log) {
    str_delete(&(log->message));
    str_delete(&(log->tag));
}

string_t log_generate_string(log_t* log) {
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