#ifndef _LIB_DATA_H
#define _LIB_DATA_H

#include <ndpi_typedefs.h>
#include <ndpi_api.h>
#include <json-c/json.h>
#include "stdint.h"
#include "reader_util.h"

#include "lib-string.h"

// TODO: Document
// Structs
struct data_memory {
    uint32_t mem_once;
    uint32_t mem_per_flow;
    uint32_t mem_actual;
    uint32_t mem_peak;
};

struct data_time {
    uint32_t setup_time;
    uint32_t processing_time;
};

struct data_traffic {
    uint64_t ethernet_bytes;
    uint64_t discarded_bytes;
    uint64_t total_packets;
    uint64_t ip_packets;
    uint64_t ip_bytes;
    uint64_t unique_flows;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t vlan_packets;
    uint64_t mpls_packets;
    uint64_t ppoe_packets;
    uint64_t fragmented_packets;
    uint64_t max_packet_size;
    uint64_t packet_less_64;
    uint64_t packet_range_64_to_128;
    uint64_t packet_range_128_to_256;
    uint64_t packet_range_256_to_1024;
    uint64_t packet_range_1024_to_1500;
    uint64_t packet_larger_1500;
};

struct data_dpi {
    float ndpi_packets_per_second;
    float ndpi_bytes_per_second;
    int64_t start_time;
    int64_t end_time;
    float traffic_packets_per_second;
    float traffic_bytes_per_second;
    uint32_t guessed_flow_protocols;
    uint64_t dpi_tcp;
    uint64_t dpi_udp;
    uint64_t dpi_other;
};

struct data_protocol {
    string_t name;
    uint64_t packet_count;
    uint64_t byte_count;
    uint64_t flow_count;
};

struct data_classification {
    string_t name;
    uint64_t packet_count;
    uint64_t byte_count;
    uint64_t flow_count;
};

struct data_risk {
    string_t name;
    uint64_t count;
    float ratio;
};

// _TODO Protocol Data

// Externs
extern u_int32_t current_ndpi_memory, max_ndpi_memory;
extern struct timeval pcap_start, pcap_end;
extern u_int8_t live_capture;

// Functions
struct data_memory data_memory_get();
json_object* data_memory_to_json(struct data_memory* data);

/* ********************************** */

struct data_time data_time_get(uint64_t processing_time_usec, uint64_t setup_time_usec);
json_object* data_time_to_json(struct data_time* data);

/* ********************************** */

struct data_traffic data_traffic_get(ndpi_stats_t stats);
json_object* data_traffic_to_json(struct data_traffic* data);

/* ********************************** */

struct data_dpi data_dpi_get(ndpi_stats_t stats, uint64_t processing_time_usec);
json_object* data_dpi_to_json(struct data_dpi* data);

/* ********************************** */

struct data_protocol data_protocol_get(char* name, uint64_t packet_count, uint64_t byte_count, uint64_t flow_count);
void data_protocol_clean(struct data_protocol* data);
json_object* data_protocol_to_json(struct data_protocol* data);

/* ********************************** */

struct data_classification data_classification_get(char* name, uint64_t packet_count, uint64_t byte_count, uint64_t flow_count);
void data_classification_clean(struct data_classification* data);
json_object* data_classification_to_json(struct data_classification* data);

/* ********************************** */

#endif