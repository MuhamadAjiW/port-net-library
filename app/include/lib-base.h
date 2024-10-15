#ifndef _LIB_BASE_H
#define _LIB_BASE_H

#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))

#ifndef bool
#define bool uint8_t
#endif

#define true 1
#define false 0
#define NULL_CHAR '\0'

#endif