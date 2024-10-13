#ifndef _LIB_PRINT_NCURSES_H
#define _LIB_PRINT_NCURSES_H

#include "lib-analytics.h"
#include <ncurses.h>

void ncurses_printResults(u_int64_t processing_time_usec, u_int64_t setup_time_usec);
void ncurses_printRiskStats();

#endif