#ifndef _LIB_ZMQ_H
#define _LIB_ZMQ_H

#include <zmq.h>
#include <stdio.h>
#include "lib-string.h"

// TODO: Document
void send_to_server(char* ip, int port, FILE* file);

#endif