#ifndef _LIB_THREAD_POOL_H
#define _LIB_THREAD_POOL_H

#include <pthread.h>
#include "_app_global.h"
#include "lib-base.h"
#include "stdint.h"
#include "stdlib.h"

// TODO: Document
#define INIT_TASK_SIZE 8

// Structs
struct thread_pool_task {
    void* (*routine)(void*);
    void* __restrict__ arg;
    void** thread_return;
};

struct thread_pool_handler {
    pthread_t thread;
    pthread_mutex_t thread_mutex;
    int thread_queue_len;
    int thread_queue_size;
    struct thread_pool_task* thread_queue;
    pthread_cond_t task_signal;
    bool __runner_flag;
};

struct thread_pool {
    struct thread_pool_handler* handler;
    pthread_mutex_t pool_mutex;
    int size;
};

struct thread_pool_runner_args {
    struct thread_pool* pool;
    int index;
};

// Functions
void thread_pool_init(struct thread_pool*, int size);
void thread_pool_delete();
void thread_pool_assign(
    struct thread_pool* pool,
    int subthread_idx,
    void* (*__start_routine)(void*),
    void* __restrict__ __arg,
    void** thread_return
);
void* thread_pool_runner(void* thread_pool_runner_args);

#endif