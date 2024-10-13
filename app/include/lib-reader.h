#ifndef _NDPIREADER_H
#define _NDPIREADER_H

#include <ndpi_typedefs.h>
#include <ndpi_api.h>
#include <float.h>
#include <math.h>
#include "uthash.h"
#include "reader_util.h"
#include "lib-receiver.h"

// _TODO: Break down further into smaller libs

// Macros
// #define DEBUG_TRACE

#define MAX_NUM_CFGS 32

#define WIRESHARK_NTOP_MAGIC 0x19680924
#define WIRESHARK_METADATA_SIZE		192
#define WIRESHARK_FLOW_RISK_INFO_SIZE	128
#define WIRESHARK_METADATA_SERVERNAME	0x01
#define WIRESHARK_METADATA_JA4C		0x02

#define NUM_DOH_BINS 2

#define ntohl64(x) ( ( (uint64_t)(ntohl( (uint32_t)((x << 32) >> 32) )) << 32) | ntohl( ((uint32_t)(x >> 32)) ) )
#define htonl64(x) ntohl64(x)

#define HEURISTICS_CODE 1

#ifndef IPVERSION
#define	IPVERSION	4 /* on *nix it is defined in netinet/ip.h */ 
#endif

// Structs
struct info_pair {
    u_int32_t addr;
    u_int8_t version; /* IP version */
    char proto[16]; /*app level protocol*/
    int count;
};

// struct associated to a workflow for a thread
struct reader_thread {
    struct ndpi_workflow* workflow;
    pthread_t pthread;
    u_int64_t last_idle_scan_time;
    u_int32_t idle_scan_idx;
    u_int32_t num_idle_flows;
    struct ndpi_flow_info* idle_flows[IDLE_SCAN_BUDGET];
};

// struct to add more statitcs in function printFlowStats
typedef struct hash_stats {
    char* domain_name;
    int occurency;       /* how many time domain name occury in the flow */
    UT_hash_handle hh;   /* hashtable to collect the stats */
}hash_stats;

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

struct cfg {
    char* proto;
    char* param;
    char* value;
};

struct ndpi_packet_tlv {
    u_int16_t type;
    u_int16_t length;
    unsigned char data[];
};

PACK_ON
struct ndpi_packet_trailer {
    u_int32_t magic; /* WIRESHARK_NTOP_MAGIC */
    ndpi_master_app_protocol proto;
    char name[16];
    u_int8_t flags;
    ndpi_risk flow_risk;
    u_int16_t flow_score;
    u_int16_t flow_risk_info_len;
    char flow_risk_info[WIRESHARK_FLOW_RISK_INFO_SIZE];
    /* TLV of attributes. Having a max and fixed size for all the metadata
       is not efficient but greatly improves detection of the trailer by Wireshark */
    u_int16_t metadata_len;
    unsigned char metadata[WIRESHARK_METADATA_SIZE];
} PACK_OFF;

// ID tracking
typedef struct ndpi_id {
    u_int8_t ip[4];                   // Ip address
    struct ndpi_id_struct* ndpi_id;  // nDpi worker structure
} ndpi_id_t;

// Externs
extern struct ndpi_stats cumulative_stats;
extern u_int8_t num_threads;
extern struct reader_thread ndpi_thread_info[MAX_NUM_READER_THREADS];
extern int enable_malloc_bins;
extern u_int8_t verbose, enable_flow_stats;
extern u_int8_t stats_flag;
extern u_int8_t shutdown_app, quiet_mode;
extern u_int32_t current_ndpi_memory, max_ndpi_memory;
extern u_int8_t live_capture;
extern struct timeval pcap_start, pcap_end;
extern u_int8_t dump_internal_stats;
extern FILE* results_file;
extern struct ndpi_bin malloc_bins;
extern struct single_flow_info* scannerHosts;
extern struct port_stats* srcStats, * dstStats;
extern struct receiver* receivers, * topReceivers;
extern int malloc_size_stats;
extern u_int32_t risk_stats[NDPI_MAX_RISK], risks_found, flows_with_risks;
extern u_int8_t enable_realtime_output, enable_protocol_guess, enable_payload_analyzer, num_bin_clusters, extcap_exit;
extern struct flow_info* all_flows;
extern u_int32_t num_flows;
extern u_int8_t enable_doh_dot_detection;
extern FILE* serialization_fp; /**< for TLV,CSV,JSON export */
extern ndpi_serialization_format serialization_format;
extern FILE* csv_fp; /**< for CSV export */
extern u_int8_t undetected_flows_deleted;
extern void ndpi_report_payload_stats(FILE* out);
extern struct ndpi_bin doh_ndpi_bins[NUM_DOH_BINS];
extern float doh_max_distance;

// Functions
void printResults(u_int64_t processing_time_usec, u_int64_t setup_time_usec);
void node_proto_guess_walker(const void* node, ndpi_VISIT which, int depth, void* user_data);
void port_stats_walker(const void* node, ndpi_VISIT which, int depth, void* user_data);
void printRiskStats();
void node_flow_risk_walker(const void* node, ndpi_VISIT which, int depth, void* user_data);
void deletePortsStats(struct port_stats* stats);
void deleteScanners(struct single_flow_info* scanners);
void freeIpTree(addr_node* root);
int port_stats_sort(void* _a, void* _b);
void printPortStats(struct port_stats* stats);
int hash_stats_sort_to_order(void* _a, void* _b);
int hash_stats_sort_to_print(void* _a, void* _b);
int info_pair_cmp(const void* _a, const void* _b);
void printFlowsStats();
void node_print_known_proto_walker(const void* node,
    ndpi_VISIT which, int depth, void* user_data);
int cmpFlows(const void* _a, const void* _b);
void node_print_unknown_proto_walker(const void* node,
    ndpi_VISIT which, int depth, void* user_data);
void printFlowSerialized(struct ndpi_flow_info* flow);
void printFlow(u_int32_t id, struct ndpi_flow_info* flow, u_int16_t thread_id);
void print_bin(FILE* fout, const char* label, struct ndpi_bin* b);
char* print_cipher(ndpi_cipher_weakness c);
void print_ndpi_address_port_file(FILE* out, const char* label, ndpi_address_port* ap);
char* is_unsafe_cipher(ndpi_cipher_weakness c);
u_int check_bin_doh_similarity(struct ndpi_bin* bin, float* similarity);
void updatePortStats(struct port_stats** stats, u_int32_t port,
    u_int32_t addr, u_int8_t version,
    u_int32_t num_pkts, u_int32_t num_bytes,
    const char* proto);
void updateScanners(struct single_flow_info** scanners, u_int32_t saddr,
    u_int8_t version, u_int32_t dport);
char* formatPackets(float numPkts, char* buf);
char* formatBytes(u_int32_t howMuch, char* buf, u_int buf_len);
void updateTopIpAddress(u_int32_t addr, u_int8_t version, const char* proto,
    int count, struct info_pair top[], int size);
void flowGetBDMeanandVariance(struct ndpi_flow_info* flow);
double ndpi_flow_get_byte_count_entropy(const uint32_t byte_count[256], unsigned int num_bytes);
int updateIpTree(u_int32_t key, u_int8_t version,
    addr_node** vrootp, const char* proto);
char* formatTraffic(float numBits, int bits, char* buf);

#endif
