#ifndef _LIB_NDPI_H
#define _LIB_NDPI_H

#include <ndpi_typedefs.h>
#include <ndpi_api.h>
#include <float.h>
#include <math.h>
#include <pthread.h>
#include "uthash.h"
#include "reader_util.h"
#include "lib-receiver.h"
#include "lib-scanner.h"
#include "lib-reader.h"

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

// Structs
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
extern void ndpi_report_payload_stats(FILE* out);
extern struct ndpi_bin doh_ndpi_bins[NUM_DOH_BINS];
extern float doh_max_distance;

// Functions
u_int check_bin_doh_similarity(struct ndpi_bin* bin, float* similarity);
char* formatPackets(float numPkts, char* buf);
char* formatBytes(u_int32_t howMuch, char* buf, u_int buf_len);
char* formatTraffic(float numBits, int bits, char* buf);
double ndpi_flow_get_byte_count_entropy(const uint32_t byte_count[256], unsigned int num_bytes);

#endif
