#ifndef _LIB_PRINT_H
#define _LIB_PRINT_H

#include "lib-analytics.h"

// TODO: Document
void print_result(u_int64_t processing_time_usec, u_int64_t setup_time_usec);
void print_risk_stats();
void print_flows_stats();
void print_flow(u_int32_t id, struct ndpi_flow_info* flow, u_int16_t thread_id);
void print_flow_serialized(struct ndpi_flow_info* flow);
void print_bin(FILE* fout, const char* label, struct ndpi_bin* b);
void print_ndpi_address_port_file(FILE* out, const char* label, ndpi_address_port* ap);


#endif