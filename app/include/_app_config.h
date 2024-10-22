#ifndef _APP_CONFIG_H
#define _APP_CONFIG_H

#include "lib-threadpool.h"

#define SUBTHREADS_DISPLAY 0
#define SUBTHREADS_ZMQ 1
#define SUBTHREADS_LOG 2

extern struct thread_pool_t thread_pool;

#endif