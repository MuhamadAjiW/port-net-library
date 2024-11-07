#ifndef _LIB_DATA_H
#define _LIB_DATA_H

#include <ndpi_typedefs.h>
#include <ndpi_api.h>
#include <json-c/json.h>
#include "stdint.h"
#include "reader_util.h"

#include "lib-analytics.h"
#include "lib-flow.h"
#include "lib-string.h"
#include "lib-array.h"

// Enums
enum packet_len {
    PACKET_LESS_64,
    PACKET_RANGE_64_128,
    PACKET_RANGE_128_256,
    PACKET_RANGE_256_1024,
    PACKET_RANGE_1024_1500,
    PACKET_MORE_1500,
};

enum flow_type {
    FLOW_TCP,
    FLOW_UDP,
    FLOW_OTHER
};

// Structs
struct data_memory {
    uint32_t mem_once;
    uint32_t mem_per_flow;
    uint32_t mem_actual;
    uint32_t mem_peak;
};

struct data_time {
    uint64_t setup_time;
    uint64_t processing_time;
};

struct data_traffic {
    int64_t start_time, end_time;
    uint64_t raw_packet_count;
    uint64_t ip_packet_count;
    uint64_t total_wire_bytes, total_ip_bytes, total_discarded_bytes;
    uint64_t tcp_count, udp_count;
    uint64_t mpls_count, pppoe_count, vlan_count, fragmented_count;
    uint64_t packet_len[PACKET_LENGTH_CLASSIFICATION_COUNT];
    uint64_t flow_confidence[NDPI_CONFIDENCE_MAX];
    uint64_t num_dissector_calls;
    float ndpi_packets_per_second, ndpi_bytes_per_second;
    float traffic_duration;
    float traffic_packets_per_second, traffic_bytes_per_second;
    uint32_t avg_pkt_size;
    uint32_t ndpi_flow_count;
    uint32_t dpi_flow_count[FLOW_TYPE_CLASSIFICATION_COUNT];
    uint32_t dpi_packet_count[FLOW_TYPE_CLASSIFICATION_COUNT];
    uint32_t guessed_flow_protocols;
    uint16_t max_packet_len;
};

struct data_detail {
    struct ndpi_lru_cache_stats lru_stats[NDPI_LRUCACHE_MAX];
    struct ndpi_automa_stats automa_stats[NDPI_AUTOMA_MAX];
    struct ndpi_patricia_tree_stats patricia_stats[NDPI_PTREE_MAX];
};

struct data_protocol {
    string_t name;
    uint64_t packet_count;
    uint64_t byte_count;
    uint32_t flow_count;
};

struct data_classification {
    string_t name;
    uint64_t packet_count;
    uint64_t byte_count;
    uint64_t flow_count;
};

struct data_risk {
    string_t name;
    uint32_t flow_count;
    float ratio;
};

struct data_all {
    struct data_memory memory;
    struct data_time time;
    struct data_traffic traffic;
    struct data_detail detail;
    dynarray_t protocol;
    dynarray_t classification;
    dynarray_t risk;
    dynarray_t known_flow;
    dynarray_t unknown_flow;
    uint32_t risky_flow_count;
};

// Externs
extern u_int32_t current_ndpi_memory, max_ndpi_memory;
extern struct timeval pcap_start, pcap_end;
extern u_int8_t live_capture;

// Functions
json_object* data_memory_to_json(struct data_memory* data);

/* ********************************** */

json_object* data_time_to_json(struct data_time* data);

/* ********************************** */

json_object* data_traffic_to_json(struct data_traffic* data);

/* ********************************** */

void data_protocol_get(
    struct data_protocol* data_protocol,
    char* name,
    uint64_t packet_count,
    uint64_t byte_count,
    uint64_t flow_count
);
void data_protocol_clean(struct data_protocol* data);
json_object* data_protocol_to_json(struct data_protocol* data);

/* ********************************** */

void data_classification_get(
    struct data_classification* data_classification,
    char* name,
    uint64_t packet_count,
    uint64_t byte_count,
    uint64_t flow_count
);
void data_classification_clean(struct data_classification* data);
json_object* data_classification_to_json(struct data_classification* data);

/* ********************************** */

void data_risk_get(
    struct data_risk* data_risk,
    char* name,
    uint64_t flow_count,
    float ratio
);
void data_risk_clean(struct data_risk* data);
json_object* data_risk_to_json(struct data_risk* data);

/* ********************************** */

json_object* data_flow_to_json(struct flow_info* data);

#endif