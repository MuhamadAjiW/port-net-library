#ifndef _LIB_PRINT_NCURSES_H
#define _LIB_PRINT_NCURSES_H

#include "lib-print.h"
#include <ncurses.h>

// TODO: Document
void* ncurses_print_result(void* processing_time_usec_arg);
void ncurses_print_risk_stats();
void ncurses_print_flows_stats();
char* ncurses_print_cipher(ndpi_cipher_weakness c);
void ncurses_print_flow(u_int32_t id, struct ndpi_flow_info* flow, u_int16_t thread_id);
void ncurses_print_flow_serialized(struct ndpi_flow_info* flow);
void ncurses_print_bin(const char* label, struct ndpi_bin* b);
void ncurses_print_ndpi_address_port_file(const char* label, ndpi_address_port* ap);


#endif