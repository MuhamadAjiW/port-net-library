#ifndef _LIB_ZMQ_H
#define _LIB_ZMQ_H

#include <zmq.h>
#include <stdio.h>
#include <pthread.h>
#include <json-c/json.h>
#include "lib-base.h"

// TODO: Document
struct lzmq_interface_t {
    void* context;
    void* socket;
    int type;
    pthread_mutex_t mutex;
};

// Externs
extern int lzmq_do_loop;

// Functions
void lzmq_int_init(struct lzmq_interface_t* lzmq_int, char* ip, int port, int type);
bool lzmq_int_initialized(struct lzmq_interface_t* interface);
void lzmq_int_cleanup(struct lzmq_interface_t* interface);
uint8_t lzmq_send_file(struct lzmq_interface_t* interface, FILE* file, int flags);
uint8_t lzmq_send_str(struct lzmq_interface_t* interface, const char* data, int flags);
uint8_t lzmq_send_json(struct lzmq_interface_t* interface, json_object* json, int flags);

#endif