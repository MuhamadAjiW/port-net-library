#ifndef _LIB_PRINT_NCURSES_H
#define _LIB_PRINT_NCURSES_H

#include "lib-analytics.h"
#include <ncurses.h>

void ncurses_printResults(u_int64_t processing_time_usec, u_int64_t setup_time_usec);
void ncurses_printRiskStats();
void ncurses_printFlowsStats();
char* ncurses_print_cipher(ndpi_cipher_weakness c);
void ncurses_printFlow(u_int32_t id, struct ndpi_flow_info* flow, u_int16_t thread_id);
void ncurses_printFlowSerialized(struct ndpi_flow_info* flow);
void ncurses_print_bin(FILE* fout, const char* label, struct ndpi_bin* b);
void ncurses_print_ndpi_address_port_file(FILE* out, const char* label, ndpi_address_port* ap);


#endif