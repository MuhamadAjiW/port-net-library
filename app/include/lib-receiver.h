#ifndef _LIB_READER_H
#define _LIB_READER_H

#include <ndpi_typedefs.h>
#include <ndpi_api.h>
#include "uthash.h"

// Structs
// struct to hold top receiver hosts
struct receiver {
    u_int32_t addr; /* key */
    u_int8_t version; /* IP version */
    u_int32_t num_pkts;
    UT_hash_handle hh;
};

// Functions
void receivers_delete(struct receiver* rcvrs);
void receivers_update(struct receiver** rcvrs, u_int32_t dst_addr,
    u_int8_t version, u_int32_t num_pkts,
    struct receiver** topRcvrs);
int receivers_sort_asc(void* _a, void* _b);
struct receiver* receivers_cut_back_to(struct receiver** rcvrs, u_int32_t size, u_int32_t max);
int receivers_acceptable(u_int32_t num_pkts);
void receivers_merge_tables(struct receiver** primary, struct receiver** secondary);

#endif