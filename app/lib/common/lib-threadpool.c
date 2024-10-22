#include "../../include/lib-threadpool.h"

void thread_pool_init(struct thread_pool_t* pool, int size) {
    pool->size = size;
    pool->handler = (struct thread_pool_handler_t*)malloc(sizeof(struct thread_pool_handler_t) * size);
    pthread_mutex_init(&pool->pool_mutex, NULL);

    for (int i = 0; i < size; i++) {
        pool->handler[i].thread_queue = (struct thread_pool_task_t*)malloc(sizeof(struct thread_pool_task_t) * INIT_TASK_SIZE);
        pool->handler[i].thread_queue_size = INIT_TASK_SIZE;
        pthread_mutex_init(&pool->handler[i].thread_mutex, NULL);

        struct thread_pool_runner_args_t* args = (struct thread_pool_runner_args_t*)malloc(sizeof(struct thread_pool_runner_args_t));
        args->index = i;
        args->pool = pool;

        pthread_create(&pool->handler[i].thread, NULL, thread_pool_runner, args);
    }
}

void thread_pool_delete(struct thread_pool_t* pool) {
    for (int i = 0; i < pool->size; i++) {
        pool->handler[i].__runner_flag = 0;
        pthread_join(pool->handler[i].thread, NULL);
        pthread_mutex_destroy(&pool->handler[i].thread_mutex);
        free(pool->handler[i].thread_queue);
    }
    pthread_mutex_destroy(&pool->pool_mutex);
    free(pool->handler);
}

void thread_pool_assign(
    struct thread_pool_t* pool,
    int subthread_idx,
    void* (*routine)(void*),
    void* __restrict__ arg,
    void** thread_return
) {
    pthread_mutex_lock(&(pool->handler[subthread_idx].thread_mutex));
    int index = pool->handler[subthread_idx].thread_queue_len++;
    if (index > pool->handler[subthread_idx].thread_queue_size) {
        pool->handler[subthread_idx].thread_queue = (struct thread_pool_task_t*)
            realloc(pool->handler[subthread_idx].thread_queue, sizeof(struct thread_pool_task_t) * pool->handler[subthread_idx].thread_queue_size * 2);
        pool->handler[subthread_idx].thread_queue_size *= 2;
    }

    pool->handler[subthread_idx].thread_queue[index].routine = routine;
    pool->handler[subthread_idx].thread_queue[index].arg = arg;
    pool->handler[subthread_idx].thread_queue[index].thread_return = thread_return;

    if (pool->handler[subthread_idx].thread_queue_len > 0) {
        pthread_cond_signal(&(pool->handler[subthread_idx].task_signal));
    }

    pthread_mutex_unlock(&(pool->handler[subthread_idx].thread_mutex));
}

void* thread_pool_runner(void* thread_pool_runner_args) {
    struct thread_pool_runner_args_t* args = (struct thread_pool_runner_args_t*)thread_pool_runner_args;
    struct thread_pool_t* pool = args->pool;
    int index = args->index;

    while (pool->handler[index].__runner_flag) {
        while (pool->handler[index].thread_queue_len == 0) {
            pthread_cond_wait(&pool->handler[index].task_signal, &(pool->handler[index].thread_mutex));
        }

        struct thread_pool_task_t* task = &pool->handler[index].thread_queue[0];
        if (task->thread_return != NULL) {
            *task->thread_return = task->routine(task->arg);
        }
        else {
            task->routine(task->arg);
        }

        // _TODO: Optimize with circular list
        pthread_mutex_lock(&(pool->handler[index].thread_mutex));
        for (int i = 0; i < pool->handler[index].thread_queue_len - 1; i++) {
            pool->handler[index].thread_queue[i] = pool->handler[index].thread_queue[i + 1];
        }

        pool->handler[index].thread_queue_len--;
        pthread_mutex_unlock(&(pool->handler[index].thread_mutex));
    }

    free(args);

    return NULL;
}