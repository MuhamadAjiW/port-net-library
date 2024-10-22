#ifndef _APP_GLOBAL_H
#define _APP_GLOBAL_H

#include "lib-threadpool.h"
#include "lib-log.h"

#define THREAD_DISPLAY 0
#define THREAD_ZMQ 1
#define THREAD_LOG 2

#define DEFAULT_LOGGER_TYPE LOGGER_TYPE_FILE
#define DEFAULT_LOGGER_PATH "./ndpiReader.log"

#define ELOG(tag, message) \
    logger_log_raw(&global_logger, LOG_LEVEL_ERROR, tag, message)
#define WLOG(tag, message) \
    logger_log_raw(&global_logger, LOG_LEVEL_WARNING, tag, message)
#define ILOG(tag, message) \
    logger_log_raw(&global_logger, LOG_LEVEL_INFO, tag, message)
#define DLOG(tag, message) \
    logger_log_raw(&global_logger, LOG_LEVEL_DEBUG, tag, message)
#define LLOG(level, tag, message) \
    logger_log_raw(&global_logger, level, tag, message)

extern struct thread_pool_t global_thread_pool;
extern struct logger_t global_logger;

uint8_t global_init();
uint8_t global_clean();

#endif