#ifndef _LIB_NDPI_H
#define _LIB_NDPI_H

#include <ndpi_typedefs.h>

// Macros
// #define DEBUG_TRACE
// #define DEPLOY_BUILD 1

#define MAX_NUM_CFGS 32

#define WIRESHARK_NTOP_MAGIC 0x19680924
#define WIRESHARK_METADATA_SIZE		192
#define WIRESHARK_FLOW_RISK_INFO_SIZE	128
#define WIRESHARK_METADATA_SERVERNAME	0x01
#define WIRESHARK_METADATA_JA4C		0x02

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

#endif