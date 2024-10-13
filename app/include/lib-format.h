#ifndef _LIB_FORMAT_H
#define _LIB_FORMAT_H

#include <ndpi_typedefs.h>
#include <ndpi_api.h>
#include <float.h>
#include <math.h>
#include <pthread.h>
#include "uthash.h"
#include "reader_util.h"
#include "lib-receiver.h"
#include "lib-scanner.h"
#include "lib-reader.h"

// Functions
char* formatPackets(float numPkts, char* buf);
char* formatBytes(u_int32_t howMuch, char* buf, u_int buf_len);
char* formatTraffic(float numBits, int bits, char* buf);

#endif
