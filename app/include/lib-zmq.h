#ifndef _LIB_ZMQ_H
#define _LIB_ZMQ_H

#include <zmq.h>
#include <stdio.h>

// TODO: Document
extern int lzmq_do_loop;

uint8_t lzmq_send_to_server(char* ip, int port, FILE* file);
void* lzmq_do_nothing(void* arg);

#endif