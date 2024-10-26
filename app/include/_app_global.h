#ifndef _APP_GLOBAL_H
#define _APP_GLOBAL_H

#include "lib-data.h"
#include "lib-threadpool.h"
#include "lib-zmq.h"
#include "lib-log.h"

#define THREAD_DISPLAY 0
#define THREAD_ZMQ 1
#define THREAD_LOG 2

#define DEFAULT_LOGGER_TYPE LOGGER_TYPE_FILE
#define DEFAULT_LOGGER_PATH "./ndpiReader.log"

#ifndef DISABLE_LOG
#define ELOG(tag, message, ...) \
    logger_log_raw(&global_logger, LOG_LEVEL_ERROR, tag, message, ##__VA_ARGS__)
#define WLOG(tag, message, ...) \
    logger_log_raw(&global_logger, LOG_LEVEL_WARNING, tag, message, ##__VA_ARGS__)
#define ILOG(tag, message, ...) \
    logger_log_raw(&global_logger, LOG_LEVEL_INFO, tag, message, ##__VA_ARGS__)
#define DLOG(tag, message, ...) \
    logger_log_raw(&global_logger, LOG_LEVEL_DEBUG, tag, message, ##__VA_ARGS__)
#define LLOG(level, tag, message, ...) \
    logger_log_raw(&global_logger, level, tag, message, ##__VA_ARGS__)
#else
#define ELOG(tag, message, ...)
#define WLOG(tag, message, ...)
#define ILOG(tag, message, ...)
#define DLOG(tag, message, ...)
#define LLOG(level, tag, message, ...)
#endif

#define TAG_GENERAL     "GENERAL"
#define TAG_THREADING   "THREAD"
#define TAG_NDPI        "NDPI"
#define TAG_DISPLAY     "DISPLAY"
#define TAG_ZMQ         "ZMQ"
#define TAG_DATA        "DATA"

// _TODO: Restructure other global variables here
extern struct thread_pool global_thread_pool;
extern struct logger global_logger;
extern struct lzmq_interface global_zmq_conn;
extern char* global_zmq_server_addr;
extern int global_zmq_server_port;
extern struct data_all global_data;

uint8_t global_init();
uint8_t global_clean();

#endif