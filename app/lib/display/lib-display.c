#include "../../include/lib-display.h"

int ldis_do_loop = 1;

void* ldis_print(__attribute__((unused)) void* arg) {
    DLOG(TAG_DISPLAY, "Starting display...");
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
        // printw("\n[DEV] Non printing test stats: %ld\n", ndpi_thread_info[0].workflow->stats.total_wire_bytes);

        gettimeofday(&end, NULL);
        u_int64_t processing_time_usec = (u_int64_t)end.tv_sec * 1000000 + end.tv_usec - ((u_int64_t)begin.tv_sec * 1000000 + begin.tv_usec);
        u_int64_t setup_time_usec = (u_int64_t)begin.tv_sec * 1000000 + begin.tv_usec - ((u_int64_t)startup_time.tv_sec * 1000000 + startup_time.tv_usec);

        global_data_generate(processing_time_usec, setup_time_usec);
        ncurses_printResults(processing_time_usec, setup_time_usec);
        thread_pool_assign(&global_thread_pool, THREAD_ZMQ, global_data_send, NULL, NULL);

        refresh();
        ncurses_clean_twalk();
        napms(1000);
    }
    endwin();
#endif

    printf("Done, closing display\n");
    DLOG(TAG_DISPLAY, "Closing display...");
    return EXIT_SUCCESS;
}
