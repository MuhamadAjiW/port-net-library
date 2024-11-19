#ifndef _LIB_BASE_H
#define _LIB_BASE_H

#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))
#define increment_wrap(index, max_size) (((index) + 1) % (max_size))
#define decrement_wrap(index, max_size) (((index) - 1) % (max_size))
#define add_wrap(index, amount, max_size) (((index) + amount) % (max_size))
#define sub_wrap(index, amount, max_size) (((index) - amount) % (max_size))

#ifndef bool
#define bool uint8_t
#endif

#define true 1
#define false 0
#define NULL_CHAR '\0'

#endif