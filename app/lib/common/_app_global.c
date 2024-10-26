#include "../../include/_app_global.h"


struct thread_pool_t global_thread_pool;
struct logger_t global_logger;
struct lzmq_interface_t global_zmq_conn;

// _TODO: use environment variable files instead
char* global_zmq_server_addr = "127.0.0.1";
int global_zmq_server_port = 56;
struct data_all_t global_data;

uint8_t global_init() {
    thread_pool_init(&global_thread_pool, INIT_TASK_SIZE);
    logger_init(&global_logger, DEFAULT_LOGGER_TYPE, DEFAULT_LOGGER_PATH, 0);
    // logger_init(&global_logger, LOGGER_TYPE_ZMQ, "127.0.0.1", 8888);
    lzmq_int_init(&global_zmq_conn, global_zmq_server_addr, global_zmq_server_port, ZMQ_PUB);
    return 1;
}

uint8_t global_clean() {
    thread_pool_delete(&global_thread_pool);
    logger_delete(&global_logger);
    lzmq_int_cleanup(&global_zmq_conn);
    return 1;
}
