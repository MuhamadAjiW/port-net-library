#include "../../include/lib-threadpool.h"

void thread_pool_init(struct thread_pool* pool, int size) {
    pool->size = size;
    pool->handler = (struct thread_pool_handler*)ndpi_malloc(sizeof(struct thread_pool_handler) * size);
    pthread_mutex_init(&pool->pool_mutex, NULL);

    for (int i = 0; i < size; i++) {
        pool->handler[i].task_queue = (struct thread_pool_task*)ndpi_malloc(sizeof(struct thread_pool_task) * INIT_TASK_SIZE);
        pool->handler[i].task_queue_first = 0;
        pool->handler[i].task_queue_last = 0;
        pool->handler[i].task_queue_len = 0;
        pool->handler[i].task_queue_size = INIT_TASK_SIZE;
        pool->handler[i].__runner_flag = 1;
        pthread_mutex_init(&pool->handler[i].thread_mutex, NULL);
        pthread_cond_init(&pool->handler[i].thread_signal, NULL);

        struct thread_pool_runner_args* args = (struct thread_pool_runner_args*)ndpi_malloc(sizeof(struct thread_pool_runner_args));
        args->index = i;
        args->pool = pool;

        pthread_create(&pool->handler[i].thread, NULL, thread_pool_runner, args);
    }
}

void thread_pool_delete(struct thread_pool* pool) {
    DLOG(TAG_THREADING, "Deleting threadpool");

    for (int i = 0; i < pool->size; i++) {
        ILOG(TAG_THREADING, "Deleting thread %d", i);
        pool->handler[i].__runner_flag = 0;
        pthread_cond_signal(&(pool->handler[i].thread_signal));
        pthread_join(pool->handler[i].thread, NULL);
        pthread_mutex_destroy(&pool->handler[i].thread_mutex);
        ndpi_free(pool->handler[i].task_queue);
    }
    pthread_mutex_destroy(&pool->pool_mutex);
    ndpi_free(pool->handler);
}

void thread_pool_assign(
    struct thread_pool* pool,
    int subthread_idx,
    void* (*routine)(void*),
    void* __restrict__ arg,
    void** thread_return
) {
    int index;

    DLOG(TAG_THREADING, "Assigning task to thread: %d", subthread_idx);
    pthread_mutex_lock(&(pool->handler[subthread_idx].thread_mutex));
    pool->handler[subthread_idx].task_queue_len++;

    if (pool->handler[subthread_idx].task_queue_len > pool->handler[subthread_idx].task_queue_size) {
        struct thread_pool_task* new_queue = (struct thread_pool_task*)
            ndpi_malloc(
                sizeof(struct thread_pool_task) * pool->handler[subthread_idx].task_queue_size * 2
            );

        index = pool->handler[subthread_idx].task_queue_first + 1;
        for (int i = 1; i < pool->handler[subthread_idx].task_queue_len; i++) {
            new_queue[i] = pool->handler[subthread_idx].task_queue[index];
            index = increment_wrap(index, pool->handler[subthread_idx].task_queue_size);
        }
        ndpi_free(pool->handler[subthread_idx].task_queue);
        pool->handler[subthread_idx].task_queue = new_queue;
        pool->handler[subthread_idx].task_queue_first = 0;
        pool->handler[subthread_idx].task_queue_last = pool->handler[subthread_idx].task_queue_size + 1;
        pool->handler[subthread_idx].task_queue_size *= 2;
    }
    else {
        pool->handler[subthread_idx].task_queue_last = increment_wrap(pool->handler[subthread_idx].task_queue_last, pool->handler[subthread_idx].task_queue_size);
    }
    index = pool->handler[subthread_idx].task_queue_last;

    pool->handler[subthread_idx].task_queue[index].routine = routine;
    pool->handler[subthread_idx].task_queue[index].arg = arg;
    pool->handler[subthread_idx].task_queue[index].thread_return = thread_return;

    if (pool->handler[subthread_idx].task_queue_len > 0) {
        pthread_cond_signal(&(pool->handler[subthread_idx].thread_signal));
    }

    pthread_mutex_unlock(&(pool->handler[subthread_idx].thread_mutex));
    DLOG(TAG_THREADING, "Task assignment to thread %d completed", subthread_idx);
}

void* thread_pool_runner(void* thread_pool_runner_args) {
    struct thread_pool_runner_args* args = (struct thread_pool_runner_args*)thread_pool_runner_args;
    struct thread_pool* pool = args->pool;
    int index = args->index;

    while (pool->handler[index].__runner_flag) {
        while (!pool->handler[index].task_queue_len) {
            pthread_cond_wait(&pool->handler[index].thread_signal, &(pool->handler[index].thread_mutex));
            if (!pool->handler[index].__runner_flag) break;
        }
        if (!pool->handler[index].__runner_flag) break;

        pool->handler[index].task_queue_first = increment_wrap(pool->handler[index].task_queue_first, pool->handler[index].task_queue_size);
        struct thread_pool_task* task = &pool->handler[index].task_queue[pool->handler[index].task_queue_first];

        if (task->thread_return != NULL) {
            *task->thread_return = task->routine(task->arg);
        }
        else {
            task->routine(task->arg);
        }
        pool->handler[index].task_queue_len--;

        pthread_mutex_unlock(&(pool->handler[index].thread_mutex));
    }

    ndpi_free(args);

    return NULL;
}
