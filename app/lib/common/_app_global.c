#include "../../include/_app_global.h"


struct thread_pool global_thread_pool;
struct logger global_logger;
struct lzmq_interface global_zmq_data_conn;
struct lzmq_interface global_zmq_flow_conn;

struct data_all global_data;

char* global_zmq_data_addr = NULL;
char* global_zmq_flow_addr = NULL;

uint8_t global_logger_type = DEFAULT_LOGGER_TYPE;
char* global_logger_path = DEFAULT_LOGGER_PATH;

uint8_t global_init() {
    thread_pool_init(&global_thread_pool, INIT_TASK_SIZE);
    logger_init(&global_logger, global_logger_type, global_logger_path);

    if (global_zmq_data_addr != NULL) {
        lzmq_int_init(&global_zmq_data_conn, global_zmq_data_addr, ZMQ_PUB);
    }
    if (global_zmq_flow_addr != NULL) {
        lzmq_int_init(&global_zmq_flow_conn, global_zmq_flow_addr, ZMQ_PUB);
    }

    return 1;
}

uint8_t global_clean() {
    thread_pool_delete(&global_thread_pool);
    logger_delete(&global_logger);
    lzmq_int_cleanup(&global_zmq_data_conn);
    lzmq_int_cleanup(&global_zmq_flow_conn);
    return 1;
}
