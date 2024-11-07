#ifndef _LIB_FLOW_H
#define _LIB_FLOW_H

#include <ndpi_typedefs.h>
#include "uthash.h"
#include "reader_util.h"

// TODO: Document
// struct to hold count of flows received by destination ports
struct port_flow_info {
    u_int32_t port; /* key */
    u_int32_t num_flows;
    UT_hash_handle hh;
};

// struct to hold single packet tcp flows sent by source ip address
struct single_flow_info {
    u_int32_t saddr; /* key */
    u_int8_t version; /* IP version */
    struct port_flow_info* ports;
    u_int32_t tot_flows;
    UT_hash_handle hh;
};

struct flow_info {
    struct ndpi_flow_info* flow;
    u_int16_t thread_id;
};

// Externs
extern u_int32_t num_flows, num_known_flows;

// Functions
int cmpFlows(const void* _a, const void* _b);

#endif