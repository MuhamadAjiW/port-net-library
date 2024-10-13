#include "../../include/lib-display.h"

int ldis_do_loop = 1;

void* ldis_print(__attribute__((unused)) void* arg) {

    u_int64_t processing_time_usec;
    u_int64_t setup_time_usec;

#ifndef __NCURSES_H

    while (ldis_do_loop) {
        gettimeofday(&end, NULL);
        processing_time_usec = (u_int64_t)end.tv_sec * 1000000 + end.tv_usec - ((u_int64_t)begin.tv_sec * 1000000 + begin.tv_usec);
        setup_time_usec = (u_int64_t)begin.tv_sec * 1000000 + begin.tv_usec - ((u_int64_t)startup_time.tv_sec * 1000000 + startup_time.tv_usec);

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
        processing_time_usec = (u_int64_t)end.tv_sec * 1000000 + end.tv_usec - ((u_int64_t)begin.tv_sec * 1000000 + begin.tv_usec);
        setup_time_usec = (u_int64_t)begin.tv_sec * 1000000 + begin.tv_usec - ((u_int64_t)startup_time.tv_sec * 1000000 + startup_time.tv_usec);

        ncurses_printResults(processing_time_usec, setup_time_usec);

        refresh();
        napms(1000);
    }

    addstr("\nPress any key to exit...");

    curs_set(true);
    refresh();
    getch();
    endwin();
#endif

    return EXIT_SUCCESS;
}
