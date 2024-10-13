#ifndef _LIB_SCANNER_H
#define _LIB_SCANNER_H

#include <ndpi_typedefs.h>
#include <ndpi_api.h>
#include "uthash.h"
#include "reader_util.h"

#include "lib-flow.h"

void deleteScanners(struct single_flow_info* scanners);
void updateScanners(struct single_flow_info** scanners, u_int32_t saddr,
    u_int8_t version, u_int32_t dport);

#endif