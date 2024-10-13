#include "../../include/lib-display.h"

int ldis_do_loop = 1;

/* Ncurses code */
void* ldis_print(__attribute__((unused)) void* arg) {
#ifndef __NCURSES_H

    while (ldis_do_loop) {
        printResults(0, 0);
    }

#else
    initscr();
    curs_set(false);

    int counter = 0;
    while (ldis_do_loop) {
        clear();

        mvprintw(0, 0, "Results: %d", counter);
        printResults(0, 0);
        counter++;

        refresh();
        napms(100);
    }

    addstr("\nPress any key to exit...");

    curs_set(true);
    refresh();
    getch();
    endwin();
#endif

    return EXIT_SUCCESS;
}
