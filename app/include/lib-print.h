#ifndef _LIB_PRINT_H
#define _LIB_PRINT_H

#include "lib-analytics.h"

void printResults(u_int64_t processing_time_usec, u_int64_t setup_time_usec);
void printRiskStats();
void printFlowsStats();
void printFlow(u_int32_t id, struct ndpi_flow_info* flow, u_int16_t thread_id);
void printFlowSerialized(struct ndpi_flow_info* flow);
void print_bin(FILE* fout, const char* label, struct ndpi_bin* b);
void print_ndpi_address_port_file(FILE* out, const char* label, ndpi_address_port* ap);


#endif