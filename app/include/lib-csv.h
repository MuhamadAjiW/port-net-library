#ifndef _LIB_CSV_H
#define _LIB_CSV_H

#include "stdio.h"
#include "stdint.h"
#include "lib-analytics.h"

void csv_print_header(FILE* csv_fp, uint8_t enable_flow_stats);
void csv_print_flow(FILE* csv_fp, struct ndpi_flow_info* flow, u_int16_t thread_id);

#endif