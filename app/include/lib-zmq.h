#ifndef _LIB_ZMQ_H
#define _LIB_ZMQ_H

#include <zmq.h>
#include <stdio.h>
#include <pthread.h>
#include <json-c/json.h>
#include "lib-base.h"

// TODO: Document
struct lzmq_interface {
    void* context;
    void* socket;
    int type;
    pthread_mutex_t mutex;
};

// Externs
extern int lzmq_do_loop;

// Functions
int lzmq_int_init(struct lzmq_interface* lzmq_int, char* addr_cp, int type);
bool lzmq_int_initialized(struct lzmq_interface* interface);
void lzmq_int_cleanup(struct lzmq_interface* interface);
uint8_t lzmq_send_file(struct lzmq_interface* interface, FILE* file, int flags);
uint8_t lzmq_send_str(struct lzmq_interface* interface, const char* data, int flags);
uint8_t lzmq_send_json(struct lzmq_interface* interface, json_object* json, int flags);

#endif