#ifndef _LIB_DISPLAY_H
#define _LIB_DISPLAY_H

#include <zmq.h>
#include <ncurses.h>
#include "lib-base.h"
#include "lib-ndpi.h"

extern int ldis_do_loop;

void* ldis_print(__attribute__((unused)) void* arg);

#endif