#ifndef _LIB_THREAD_GROUP_H
#define _LIB_THREAD_GROUP_H

#include <pthread.h>
#include "_app_global.h"
#include "lib-base.h"
#include "stdint.h"
#include "stdlib.h"

// TODO: Document
#define INIT_TASK_SIZE 8

// Structs
struct thread_group_task {
    void* (*routine)(void*);
    void* __restrict__ arg;
    void** thread_return;
};

struct thread_group_handler {
    pthread_t thread;
    pthread_mutex_t thread_mutex;
    pthread_cond_t thread_signal;
    struct thread_group_task* task_queue;
    int task_queue_first;
    int task_queue_last;
    int task_queue_len;
    int task_queue_size;
    uint8_t __runner_flag;
};

struct thread_group {
    struct thread_group_handler* handler;
    pthread_mutex_t mutex;
    int size;
};

struct thread_group_runner_args {
    struct thread_group* group;
    int index;
};

// Functions
void thread_group_init(struct thread_group*, int size);
void thread_group_delete();
void thread_group_assign(
    struct thread_group* group,
    int subthread_idx,
    void* (*__start_routine)(void*),
    void* __restrict__ __arg,
    void** thread_return
);
void* thread_group_runner(void* thread_group_runner_args);

#endif