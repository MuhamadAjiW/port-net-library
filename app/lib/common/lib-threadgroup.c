#include "../../include/lib-threadgroup.h"

void thread_group_init(struct thread_group* group, int size) {
    group->size = size;
    group->handler = (struct thread_group_handler*)ndpi_malloc(sizeof(struct thread_group_handler) * size);
    pthread_mutex_init(&group->mutex, NULL);

    for (int i = 0; i < size; i++) {
        group->handler[i].task_queue = (struct thread_group_task*)ndpi_malloc(sizeof(struct thread_group_task) * INIT_TASK_SIZE);
        group->handler[i].task_queue_first = 0;
        group->handler[i].task_queue_last = 0;
        group->handler[i].task_queue_len = 0;
        group->handler[i].task_queue_size = INIT_TASK_SIZE;
        group->handler[i].__runner_flag = 1;
        pthread_mutex_init(&group->handler[i].thread_mutex, NULL);
        pthread_cond_init(&group->handler[i].thread_signal, NULL);

        struct thread_group_runner_args* args = (struct thread_group_runner_args*)ndpi_malloc(sizeof(struct thread_group_runner_args));
        args->index = i;
        args->group = group;

        pthread_create(&group->handler[i].thread, NULL, thread_group_runner, args);
    }
}

void thread_group_delete(struct thread_group* group) {
    DLOG(TAG_THREADING, "Deleting threadgroup");

    for (int i = 0; i < group->size; i++) {
        ILOG(TAG_THREADING, "Deleting thread %d", i);
        group->handler[i].__runner_flag = 0;
        pthread_cond_signal(&(group->handler[i].thread_signal));
        pthread_join(group->handler[i].thread, NULL);
        pthread_mutex_destroy(&group->handler[i].thread_mutex);
        ndpi_free(group->handler[i].task_queue);
    }
    pthread_mutex_destroy(&group->mutex);
    ndpi_free(group->handler);
}

void thread_group_assign(
    struct thread_group* group,
    int subthread_idx,
    void* (*routine)(void*),
    void* __restrict__ arg,
    void** thread_return
) {
    int index;

    DLOG(TAG_THREADING, "Assigning task to thread: %d", subthread_idx);
    pthread_mutex_lock(&(group->handler[subthread_idx].thread_mutex));
    group->handler[subthread_idx].task_queue_len++;

    if (group->handler[subthread_idx].task_queue_len > group->handler[subthread_idx].task_queue_size) {
        struct thread_group_task* new_queue = (struct thread_group_task*)
            ndpi_malloc(
                sizeof(struct thread_group_task) * group->handler[subthread_idx].task_queue_size * 2
            );

        index = group->handler[subthread_idx].task_queue_first + 1;
        for (int i = 1; i < group->handler[subthread_idx].task_queue_len; i++) {
            new_queue[i] = group->handler[subthread_idx].task_queue[index];
            index = increment_wrap(index, group->handler[subthread_idx].task_queue_size);
        }
        ndpi_free(group->handler[subthread_idx].task_queue);
        group->handler[subthread_idx].task_queue = new_queue;
        group->handler[subthread_idx].task_queue_first = 0;
        group->handler[subthread_idx].task_queue_last = group->handler[subthread_idx].task_queue_size + 1;
        group->handler[subthread_idx].task_queue_size *= 2;
    }
    else {
        group->handler[subthread_idx].task_queue_last = increment_wrap(group->handler[subthread_idx].task_queue_last, group->handler[subthread_idx].task_queue_size);
    }
    index = group->handler[subthread_idx].task_queue_last;

    group->handler[subthread_idx].task_queue[index].routine = routine;
    group->handler[subthread_idx].task_queue[index].arg = arg;
    group->handler[subthread_idx].task_queue[index].thread_return = thread_return;

    if (group->handler[subthread_idx].task_queue_len > 0) {
        pthread_cond_signal(&(group->handler[subthread_idx].thread_signal));
    }

    pthread_mutex_unlock(&(group->handler[subthread_idx].thread_mutex));
    DLOG(TAG_THREADING, "Task assignment to thread %d completed", subthread_idx);
}

void* thread_group_runner(void* thread_group_runner_args) {
    struct thread_group_runner_args* args = (struct thread_group_runner_args*)thread_group_runner_args;
    struct thread_group* group = args->group;
    int index = args->index;

    while (group->handler[index].__runner_flag) {
        while (!group->handler[index].task_queue_len) {
            pthread_cond_wait(&group->handler[index].thread_signal, &(group->handler[index].thread_mutex));
            if (!group->handler[index].__runner_flag) break;
        }
        if (!group->handler[index].__runner_flag) break;

        group->handler[index].task_queue_first = increment_wrap(group->handler[index].task_queue_first, group->handler[index].task_queue_size);
        struct thread_group_task* task = &group->handler[index].task_queue[group->handler[index].task_queue_first];

        if (task->thread_return != NULL) {
            *task->thread_return = task->routine(task->arg);
        }
        else {
            task->routine(task->arg);
        }
        group->handler[index].task_queue_len--;

        pthread_mutex_unlock(&(group->handler[index].thread_mutex));
    }

    ndpi_free(args);

    return NULL;
}
