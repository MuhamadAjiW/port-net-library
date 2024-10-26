#ifndef _LIB_DISPLAY_H
#define _LIB_DISPLAY_H

#include <zmq.h>
#include <ncurses.h>
#include "_app_global.h"
#include "lib-base.h"
#include "lib-print.h"
#include "lib-print-ncurses.h"

// TODO: Document
extern int ldis_do_loop;
extern struct timeval startup_time, begin, end;

void* ldis_print(__attribute__((unused)) void* arg);

#endif