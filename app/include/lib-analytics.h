#ifndef _LIB_ANALYTICS_H
#define _LIB_ANALYTICS_H

#include <math.h>
#include <ndpi_typedefs.h>
#include <ndpi_api.h>
#include "reader_util.h"
#include "lib-reader.h"
#include "lib-flow.h"
#include "lib-cipher.h"
#include "lib-format.h"
#include "lib-ndpi.h"

// Macros
#define NUM_DOH_BINS 2

// Externs
extern struct ndpi_stats cumulative_stats;
extern struct reader_thread ndpi_thread_info[MAX_NUM_READER_THREADS];
extern u_int8_t num_threads;
extern u_int8_t verbose, enable_flow_stats;
extern u_int8_t stats_flag;
extern int malloc_size_stats;
extern u_int8_t shutdown_app, quiet_mode;
extern u_int32_t current_ndpi_memory, max_ndpi_memory;
extern u_int8_t live_capture;
extern struct timeval pcap_start, pcap_end;
extern u_int8_t dump_internal_stats;
extern int enable_malloc_bins;
extern FILE* results_file;
extern struct ndpi_bin malloc_bins;
extern u_int32_t risk_stats[NDPI_MAX_RISK], risks_found, flows_with_risks;
extern u_int8_t enable_realtime_output, enable_protocol_guess, enable_payload_analyzer, num_bin_clusters, extcap_exit;
extern struct flow_info* all_flows;
extern u_int8_t enable_doh_dot_detection;
extern u_int8_t undetected_flows_deleted;
extern FILE* csv_fp; /**< for CSV export */
extern FILE* serialization_fp; /**< for TLV,CSV,JSON export */
extern ndpi_serialization_format serialization_format;
extern void ndpi_report_payload_stats(FILE* out);
extern struct ndpi_bin doh_ndpi_bins[NUM_DOH_BINS];
extern float doh_max_distance;

// Functions
double ndpi_flow_get_byte_count_entropy(const uint32_t byte_count[256], unsigned int num_bytes);
u_int check_bin_doh_similarity(struct ndpi_bin* bin, float* similarity);
void flowGetBDMeanandVariance(struct ndpi_flow_info* flow);
void node_proto_guess_walker(const void* node, ndpi_VISIT which, int depth, void* user_data);
void node_flow_risk_walker(const void* node, ndpi_VISIT which, int depth, void* user_data);
void node_print_known_proto_walker(const void* node,
    ndpi_VISIT which, int depth, void* user_data);
void node_print_unknown_proto_walker(const void* node,
    ndpi_VISIT which, int depth, void* user_data);
void printResults(u_int64_t processing_time_usec, u_int64_t setup_time_usec);
void printRiskStats();
void printFlowsStats();
char* print_cipher(ndpi_cipher_weakness c);
void printFlow(u_int32_t id, struct ndpi_flow_info* flow, u_int16_t thread_id);
void printFlowSerialized(struct ndpi_flow_info* flow);
void print_bin(FILE* fout, const char* label, struct ndpi_bin* b);
void print_ndpi_address_port_file(FILE* out, const char* label, ndpi_address_port* ap);

#endif