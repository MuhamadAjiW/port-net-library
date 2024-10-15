#ifndef _LIB_READER_H
#define _LIB_READER_H

#include <ndpi_typedefs.h>
#include <ndpi_api.h>
#include "uthash.h"
#include "reader_util.h"
#include "lib-receiver.h"
#include "lib-scanner.h"
#include "lib-flow.h"

#ifndef IPVERSION
#define	IPVERSION	4 /* on *nix it is defined in netinet/ip.h */ 
#endif

// Structs
// struct associated to a workflow for a thread
struct reader_thread {
    struct ndpi_workflow* workflow;
    pthread_t pthread;
    u_int64_t last_idle_scan_time;
    u_int32_t idle_scan_idx;
    u_int32_t num_idle_flows;
    struct ndpi_flow_info* idle_flows[IDLE_SCAN_BUDGET];
    bool aggregated;
};

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

// Externs
extern struct reader_thread ndpi_thread_info[MAX_NUM_READER_THREADS];
extern struct single_flow_info* scannerHosts;
extern struct port_stats* srcStats, * dstStats;

// Functions
void port_stats_walker(const void* node, ndpi_VISIT which, int depth, void* user_data);
int port_stats_sort(void* _a, void* _b);
void port_stats_delete(struct port_stats* stats);
void port_stats_update(struct port_stats** stats, u_int32_t port,
    u_int32_t addr, u_int8_t version,
    u_int32_t num_pkts, u_int32_t num_bytes,
    const char* proto);
void port_stats_print(struct port_stats* stats);

void ip_tree_free(addr_node* root);
int ip_tree_update(u_int32_t key, u_int8_t version,
    addr_node** vrootp, const char* proto);
void ip_update_top(u_int32_t addr, u_int8_t version, const char* proto,
    int count, struct info_pair top[], int size);

int info_pair_cmp(const void* _a, const void* _b);

#endif