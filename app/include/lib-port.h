#ifndef _LIB_FLOW_H
#define _LIB_FLOW_H

#include <ndpi_typedefs.h>
#include <ndpi_api.h>
#include "uthash.h"
#include "reader_util.h"

// Structs
struct info_pair {
    u_int32_t addr;
    u_int8_t version; /* IP version */
    char proto[16]; /*app level protocol*/
    int count;
};

typedef struct node_a {
    u_int32_t addr;
    u_int8_t version; /* IP version */
    char proto[16]; /*app level protocol*/
    int count;
    struct node_a* left, * right;
}addr_node;

struct port_stats {
    u_int32_t port; /* we'll use this field as the key */
    u_int32_t num_pkts, num_bytes;
    u_int32_t num_flows;
    u_int32_t num_addr; /*number of distinct IP addresses */
    u_int32_t cumulative_addr; /*cumulative some of IP addresses */
    addr_node* addr_tree; /* tree of distinct IP addresses */
    struct info_pair top_ip_addrs[MAX_NUM_IP_ADDRESS];
    u_int8_t hasTopHost; /* as boolean flag */
    u_int32_t top_host;  /* host that is contributed to > 95% of traffic */
    u_int8_t version;    /* top host's ip version */
    char proto[16];      /* application level protocol of top host */
    UT_hash_handle hh;   /* makes this structure hashable */
};

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

// Functions

#endif