#ifndef _LIB_CIPHER_H
#define _LIB_CIPHER_H

#include <ndpi_typedefs.h>
#include "uthash.h"

// Structs
// struct to add more statitcs in function printFlowStats
typedef struct hash_stats {
    char* domain_name;
    int occurency;       /* how many time domain name occury in the flow */
    UT_hash_handle hh;   /* hashtable to collect the stats */
}hash_stats;

// Functions
char* is_unsafe_cipher(ndpi_cipher_weakness c);
char* print_cipher(ndpi_cipher_weakness c);
int hash_stats_sort_to_order(void* _a, void* _b);
int hash_stats_sort_to_print(void* _a, void* _b);

#endif