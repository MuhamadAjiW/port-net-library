#include "../../include/lib-display.h"

int ldis_do_loop = 1;

void* ldis_print(__attribute__((unused)) void* arg) {
    DLOG(TAG_DISPLAY, "Starting display...");

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
    for (int thread_id = 0; thread_id < num_threads; thread_id++) {
        memset(ndpi_thread_info[thread_id].workflow->stats.protocol_counter, 0, sizeof(ndpi_thread_info[thread_id].workflow->stats.protocol_counter));
        memset(ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes, 0, sizeof(ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes));
        memset(ndpi_thread_info[thread_id].workflow->stats.protocol_flows, 0, sizeof(ndpi_thread_info[thread_id].workflow->stats.protocol_flows));
        memset(ndpi_thread_info[thread_id].workflow->stats.flow_confidence, 0, sizeof(ndpi_thread_info[thread_id].workflow->stats.flow_confidence));
        ndpi_thread_info[thread_id].workflow->stats.guessed_flow_protocols = 0;
        ndpi_thread_info[thread_id].workflow->stats.num_dissector_calls = 0;
    }

    memset(risk_stats, 0, sizeof(risk_stats));
    flows_with_risks = 0;
    risks_found = 0;

    DLOG(TAG_DISPLAY, "Closing display...");
    return EXIT_SUCCESS;
}
