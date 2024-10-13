#include "../../include/lib-display.h"

int ldis_do_loop = 1;

void* ldis_print(__attribute__((unused)) void* arg) {
#ifndef __NCURSES_H

    while (ldis_do_loop) {
        printResults(0, 0);
    }

#else
    initscr();
    cbreak();
    noecho();
    curs_set(false);

    while (ldis_do_loop) {
        clear();
        ncurses_printResults(0, 0);
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
