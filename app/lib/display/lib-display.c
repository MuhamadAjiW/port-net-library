#include "../../include/lib-display.h"

int ldis_do_loop = 1;

void* ldis_print(__attribute__((unused)) void* arg) {
    DLOG(TAG_DISPLAY, "Starting display...");

    // _TODO: Separate data sending and screen printing

#ifndef __NCURSES_H

    while (ldis_do_loop) {
        gettimeofday(&end, NULL);
        u_int64_t processing_time_usec = (u_int64_t)end.tv_sec * 1000000 + end.tv_usec - ((u_int64_t)begin.tv_sec * 1000000 + begin.tv_usec);
        u_int64_t setup_time_usec = (u_int64_t)begin.tv_sec * 1000000 + begin.tv_usec - ((u_int64_t)startup_time.tv_sec * 1000000 + startup_time.tv_usec);

        printResults(0, 0);
    }

#else
    initscr();
    cbreak();
    noecho();
    curs_set(false);

    while (ldis_do_loop) {
        clear();
        gettimeofday(&end, NULL);
        u_int64_t processing_time_usec = (u_int64_t)end.tv_sec * 1000000 + end.tv_usec - ((u_int64_t)begin.tv_sec * 1000000 + begin.tv_usec);
        u_int64_t setup_time_usec = (u_int64_t)begin.tv_sec * 1000000 + begin.tv_usec - ((u_int64_t)startup_time.tv_sec * 1000000 + startup_time.tv_usec);

        global_data_generate(processing_time_usec, setup_time_usec, ndpi_thread_info[0].workflow->ndpi_struct);
        thread_pool_assign(&global_thread_pool, THREAD_ZMQ_PRIMARY, global_data_send, NULL, NULL);
        thread_pool_assign(&global_thread_pool, THREAD_ZMQ_SECONDARY, global_flow_send, NULL, NULL);
        ncurses_printResults((void*)&processing_time_usec);

        // printw("[DEV] That's all");

        refresh();
        napms(1000);
    }
    endwin();
#endif

    printf("Done, closing display\n");
    DLOG(TAG_DISPLAY, "Closing display...");

    data_reset_counters();
    return EXIT_SUCCESS;
}
