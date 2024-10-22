#include "../../include/_app_global.h"


struct thread_pool_t global_thread_pool;
struct logger_t global_logger;

uint8_t global_init() {
    thread_pool_init(&global_thread_pool, INIT_TASK_SIZE);
    logger_init(&global_logger, DEFAULT_LOGGER_TYPE, DEFAULT_LOGGER_PATH);
    return 1;
}

uint8_t global_clean() {
    thread_pool_delete(&global_thread_pool);
    logger_delete(&global_logger);
    return 1;
}
