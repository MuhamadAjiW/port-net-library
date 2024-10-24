/*
 * ndpiReader.c
 *
 * Copyright (C) 2011-24 - ntop.org
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "ndpi_config.h"

#ifdef __linux__
#include <sched.h>
#endif

#include "ndpi_api.h"
#include "../src/lib/third_party/include/uthash.h"
#include "../src/lib/third_party/include/ahocorasick.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <float.h> /* FLT_EPSILON */
#ifdef WIN32
#include <winsock2.h> /* winsock.h is included automatically */
#include <windows.h>
#include <ws2tcpip.h>
#include <process.h>
#include <io.h>
#else
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/mman.h>
#endif
#include <string.h>
#include <stdarg.h>
#include <search.h>
#include <pcap.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <math.h>
#include <fcntl.h>
#ifndef _MSC_BUILD
#include <libgen.h>
#endif
#include <errno.h>

#include <zmq.h>
#include <ncurses.h>
#include "include/reader_util.h"
#include "include/_build_config.h"

#ifndef DEPLOY_BUILD
#include "include/headers-test.h"
#else
#include "include/headers.h"
#endif

// Externs
extern u_int8_t enable_doh_dot_detection;
extern u_int32_t max_num_packets_per_flow, max_packet_payload_dissection, max_num_reported_top_payloads;
extern u_int16_t min_pattern_len, max_pattern_len;
extern void ndpi_report_payload_stats(FILE* out);
extern int parse_proto_name_list(char* str, NDPI_PROTOCOL_BITMASK* bitmask, int inverted_logic);

// Statics
static char* _pcap_file[MAX_NUM_READER_THREADS]; /**< Ingress pcap file/interfaces */
static char* results_path = NULL;
static char* bpfFilter = NULL; /**< bpf filter  */
static char* _protoFilePath = NULL; /**< Protocol file path */
static char* _customCategoryFilePath = NULL; /**< Custom categories file path  */
static char* _maliciousJA3Path = NULL; /**< Malicious JA3 signatures */
static char* _maliciousSHA1Path = NULL; /**< Malicious SSL certificate SHA1 fingerprints */
static char* _riskyDomainFilePath = NULL; /**< Risky domain files */
static char* _categoriesDirPath = NULL; /**< Directory containing domain files */
static char* domain_to_check = NULL;
static char* ip_port_to_check = NULL;
static u_int8_t ignore_vlanid = 0;
static struct cfg cfgs[MAX_NUM_CFGS];
static int num_cfgs = 0;
static u_int32_t pcap_analysis_duration = (u_int32_t)-1;
static u_int16_t decode_tunnels = 0;
static u_int16_t num_loops = 1;
static time_t capture_for = 0;
static time_t capture_until = 0;

#ifndef USE_DPDK
static FILE* playlist_fp[MAX_NUM_READER_THREADS] = { NULL }; /**< Ingress playlist */
static struct bpf_program bpf_code;
#else
static int dpdk_port_id = 0, dpdk_run_capture = 1;
#endif

#ifdef __linux__
static int core_affinity[MAX_NUM_READER_THREADS];
#endif

static struct bpf_program* bpf_cfilter = NULL;
static pcap_dumper_t* extcap_dumper = NULL;
static pcap_t* extcap_fifo_h = NULL;
static char extcap_buf[65536 + sizeof(struct ndpi_packet_trailer)];
static char* extcap_capture_fifo = NULL;
static u_int16_t extcap_packet_filter = (u_int16_t)-1;
static int do_extcap_capture = 0;
static int extcap_add_crc = 0;

static u_int8_t doh_centroids[NUM_DOH_BINS][PLEN_NUM_BINS] = {
  { 23,25,3,0,26,0,0,0,0,0,0,0,0,0,2,0,0,15,3,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
  { 35,30,21,0,0,0,2,4,0,0,5,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }
};

// Variables
struct timeval startup_time, begin, end;
FILE* results_file = NULL;

u_int8_t live_capture = 0;
u_int8_t undetected_flows_deleted = 0;
FILE* csv_fp = NULL; /**< for CSV export */
FILE* serialization_fp = NULL; /**< for TLV,CSV,JSON export */
ndpi_serialization_format serialization_format = ndpi_serialization_format_unknown;

FILE* fingerprint_fp = NULL; /**< for flow fingerprint export */
struct receiver* receivers = NULL, * topReceivers = NULL;

/** User preferences **/
char* addr_dump_path = NULL;
u_int8_t enable_realtime_output = 0, enable_protocol_guess = NDPI_GIVEUP_GUESS_BY_PORT | NDPI_GIVEUP_GUESS_BY_IP, enable_payload_analyzer = 0, num_bin_clusters = 0, extcap_exit = 0;
u_int8_t verbose = 0, enable_flow_stats = 0;
bool do_load_lists = false;

int reader_log_level = 0;
char* _disabled_protocols = NULL;
u_int8_t stats_flag = 0;
u_int8_t human_readeable_string_len = 5;
u_int8_t max_num_udp_dissected_pkts = 24 /* 8 is enough for most protocols, Signal and SnapchatCall require more */, max_num_tcp_dissected_pkts = 80 /* due to telnet */;
u_int32_t risk_stats[NDPI_MAX_RISK] = { 0 }, risks_found = 0, flows_with_risks = 0;
struct ndpi_stats cumulative_stats;

u_int8_t shutdown_app = 0, quiet_mode = 0;
u_int8_t num_threads = 1;

struct timeval pcap_start = { 0, 0 }, pcap_end = { 0, 0 };

u_int32_t num_flows;
u_int8_t dump_internal_stats;

struct ndpi_bin malloc_bins;
int enable_malloc_bins = 0;
int max_malloc_bins = 14;
int malloc_size_stats = 0;

struct flow_info* all_flows;

struct port_stats* srcStats = NULL, * dstStats = NULL;
struct single_flow_info* scannerHosts = NULL;

// array for every thread created for a flow
struct reader_thread ndpi_thread_info[MAX_NUM_READER_THREADS];

// used memory counters
u_int32_t current_ndpi_memory = 0, max_ndpi_memory = 0;

struct ndpi_bin doh_ndpi_bins[NUM_DOH_BINS];
float doh_max_distance = 35.5;

void run_test(); /* Forward */

/* ********************************** */

#ifdef DEBUG_TRACE
FILE* trace_fp = NULL;
#endif

/* ***************************************************** */

static u_int32_t reader_slot_malloc_bins(u_int64_t v)
{
    int i;

    /* 0-2,3-4,5-8,9-16,17-32,33-64,65-128,129-256,257-512,513-1024,1025-2048,2049-4096,4097-8192,8193- */
    for (i = 0; i < max_malloc_bins - 1; i++)
        if ((1ULL << (i + 1)) >= v)
            return i;
    return i;
}

/**
 * @brief ndpi_malloc wrapper function
 */
static void* ndpi_malloc_wrapper(size_t size) {
    current_ndpi_memory += size;

    if (current_ndpi_memory > max_ndpi_memory)
        max_ndpi_memory = current_ndpi_memory;

    if (enable_malloc_bins && malloc_size_stats)
        ndpi_inc_bin(&malloc_bins, reader_slot_malloc_bins(size), 1);

    return(malloc(size)); /* Don't change to ndpi_malloc !!!!! */
}

/* ***************************************************** */

/**
 * @brief free wrapper function
 */
static void free_wrapper(void* freeable) {
    free(freeable); /* Don't change to ndpi_free !!!!! */
}

/* ***************************************************** */

static void init_doh_bins() {
    u_int i;

    for (i = 0; i < NUM_DOH_BINS; i++) {
        ndpi_init_bin(&doh_ndpi_bins[i], ndpi_bin_family8, PLEN_NUM_BINS);
        ndpi_free_bin(&doh_ndpi_bins[i]); /* Hack: we use static bins (see below), so we need to free the dynamic ones just allocated */
        doh_ndpi_bins[i].u.bins8 = doh_centroids[i];
    }
}

/* *********************************************** */

void ndpiCheckHostStringMatch(char* testChar) {
    ndpi_protocol_match_result match = { NDPI_PROTOCOL_UNKNOWN,
      NDPI_PROTOCOL_CATEGORY_UNSPECIFIED, NDPI_PROTOCOL_UNRATED };
    int  testRes;
    char appBufStr[64];
    ndpi_protocol detected_protocol;
    struct ndpi_detection_module_struct* ndpi_str;
    NDPI_PROTOCOL_BITMASK all;

    if (!testChar)
        return;

    ndpi_str = ndpi_init_detection_module(NULL);
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_str, &all);
    ndpi_finalize_initialization(ndpi_str);

    testRes = ndpi_match_string_subprotocol(ndpi_str,
        testChar, strlen(testChar), &match);

    if (testRes) {
        memset(&detected_protocol, 0, sizeof(ndpi_protocol));

        detected_protocol.proto.app_protocol = match.protocol_id;
        detected_protocol.proto.master_protocol = 0;
        detected_protocol.category = match.protocol_category;

        ndpi_protocol2name(ndpi_str, detected_protocol, appBufStr,
            sizeof(appBufStr));

        printf("Match Found for string [%s] -> P(%d) B(%d) C(%d) => %s %s %s\n",
            testChar, match.protocol_id, match.protocol_breed,
            match.protocol_category,
            appBufStr,
            ndpi_get_proto_breed_name(match.protocol_breed),
            ndpi_category_get_name(ndpi_str, match.protocol_category));
    }
    else
        printf("Match NOT Found for string: %s\n\n", testChar);

    ndpi_exit_detection_module(ndpi_str);
}

/* *********************************************** */

static char const*
ndpi_cfg_error2string(ndpi_cfg_error const err)
{
    switch (err)
    {
    case NDPI_CFG_INVALID_CONTEXT:
        return "Invalid context";
    case NDPI_CFG_NOT_FOUND:
        return "Configuration not found";
    case NDPI_CFG_INVALID_PARAM:
        return "Invalid configuration parameter";
    case NDPI_CFG_CONTEXT_ALREADY_INITIALIZED:
        return "Configuration context already initialized";
    case NDPI_CFG_CALLBACK_ERROR:
        return "Configuration callback error";
    case NDPI_CFG_OK:
        return "Success";
    }

    return "Unknown";
}

static void ndpiCheckIPMatch(char* testChar) {
    struct ndpi_detection_module_struct* ndpi_str;
    u_int16_t ret = NDPI_PROTOCOL_UNKNOWN;
    u_int16_t port = 0;
    char* saveptr, * ip_str, * port_str;
    struct in_addr addr;
    char appBufStr[64];
    ndpi_protocol detected_protocol;
    int i;
    ndpi_cfg_error rc;
    NDPI_PROTOCOL_BITMASK all;

    if (!testChar)
        return;

    ndpi_str = ndpi_init_detection_module(NULL);
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_str, &all);

    if (_protoFilePath != NULL)
        ndpi_load_protocols_file(ndpi_str, _protoFilePath);

    for (i = 0; i < num_cfgs; i++) {
        rc = ndpi_set_config(ndpi_str, cfgs[i].proto, cfgs[i].param, cfgs[i].value);

        if (rc != NDPI_CFG_OK) {
            fprintf(stderr, "Error setting config [%s][%s][%s]: %s (%d)\n",
                (cfgs[i].proto != NULL ? cfgs[i].proto : ""),
                cfgs[i].param, cfgs[i].value, ndpi_cfg_error2string(rc), rc);
            exit(-1);
        }
    }

    ndpi_finalize_initialization(ndpi_str);

    ip_str = strtok_r(testChar, ":", &saveptr);
    if (!ip_str)
        return;

    addr.s_addr = inet_addr(ip_str);
    port_str = strtok_r(NULL, "\n", &saveptr);
    if (port_str)
        port = atoi(port_str);
    ret = ndpi_network_port_ptree_match(ndpi_str, &addr, htons(port));

    if (ret != NDPI_PROTOCOL_UNKNOWN) {
        memset(&detected_protocol, 0, sizeof(ndpi_protocol));
        detected_protocol.proto.app_protocol = ndpi_map_ndpi_id_to_user_proto_id(ndpi_str, ret);

        ndpi_protocol2name(ndpi_str, detected_protocol, appBufStr,
            sizeof(appBufStr));

        printf("Match Found for IP %s, port %d -> %s (%d)\n",
            ip_str, port, appBufStr, detected_protocol.proto.app_protocol);
    }
    else {
        printf("Match NOT Found for IP: %s\n", testChar);
    }

    ndpi_exit_detection_module(ndpi_str);
}

/********************** FUNCTIONS ********************* */

/**
 * @brief Set main components necessary to the detection
 */
static void setupDetection(u_int16_t thread_id, pcap_t* pcap_handle,
    struct ndpi_global_context* g_ctx);

/**
 * @brief Print help instructions
 */
static void help(u_int long_help) {
    printf("Welcome to nDPI %s\n\n", ndpi_revision());

    printf("ndpiReader "
#ifndef USE_DPDK
        "-i <file|device> "
#endif
        "[-f <filter>][-s <duration>][-m <duration>][-b <num bin clusters>]\n"
        "          [-p <protos>][-l <loops> [-q][-d][-h][-H][-D][-e <len>][-E <path>][-t][-v <level>]\n"
        "          [-n <threads>][-N <path>][-w <file>][-c <file>][-C <file>][-j <file>][-x <file>]\n"
        "          [-r <file>][-R][-j <file>][-S <file>][-T <num>][-U <num>] [-x <domain>]\n"
        "          [-a <mode>][-B proto_list]\n\n"
        "Usage:\n"
        "  -i <file.pcap|device>     | Specify a pcap file/playlist to read packets from or a\n"
        "                            | device for live capture (comma-separated list)\n"
        "  -f <BPF filter>           | Specify a BPF filter for filtering selected traffic\n"
        "  -s <duration>             | Maximum capture duration in seconds (live traffic capture only)\n"
        "  -m <duration>             | Split analysis duration in <duration> max seconds\n"
        "  -p <file>.protos          | Specify a protocol file (eg. protos.txt)\n"
        "  -l <num loops>            | Number of detection loops (test only)\n"
        "  -n <num threads>          | Number of threads. Default: number of interfaces in -i.\n"
        "                            | Ignored with pcap files.\n"
        "  -N <path>                 | Address cache dump/restore pathxo.\n"
        "  -b <num bin clusters>     | Number of bin clusters\n"
        "  -k <file>                 | Specify a file to write serialized detection results\n"
        "  -K <format>               | Specify the serialization format for `-k'\n"
        "                            | Valid formats are tlv, csv or json (default)\n"
#ifdef __linux__
        "  -g <id:id...>             | Thread affinity mask (one core id per thread)\n"
#endif
        "  -a <mode>                 | Generates option values for GUIs\n"
        "                            | 0 - List known protocols\n"
        "                            | 1 - List known categories\n"
        "                            | 2 - List known risks\n"
        "  -d                        | Disable protocol guess (by ip and by port) and use only DPI.\n"
        "                            | It is a shortcut to --cfg=dpi.guess_on_giveup,0\n"
        "  -e <len>                  | Min human readeable string match len. Default %u\n"
        "  -q                        | Quiet mode\n"
        "  -F                        | Enable flow stats\n"
        "  -t                        | Dissect GTP/TZSP tunnels\n"
        "  -P <a>:<b>:<c>:<d>:<e>    | Enable payload analysis:\n"
        "                            | <a> = min pattern len to search\n"
        "                            | <b> = max pattern len to search\n"
        "                            | <c> = max num packets per flow\n"
        "                            | <d> = max packet payload dissection\n"
        "                            | <d> = max num reported payloads\n"
        "                            | Default: %u:%u:%u:%u:%u\n"
        "  -c <path>                 | Load custom categories from the specified file\n"
        "  -C <path>                 | Write output in CSV format on the specified file\n"
        "  -E <path>                 | Write flow fingerprints on the specified file\n"
        "  -r <path>                 | Load risky domain file\n"
        "  -R                        | Print detected realtime protocols\n"
        "  -j <path>                 | Load malicious JA3 fingeprints\n"
        "  -S <path>                 | Load malicious SSL certificate SHA1 fingerprints\n"
        "  -G <dir>                  | Bind domain names to categories loading files from <dir>\n"
        "  -w <path>                 | Write test output on the specified file. This is useful for\n"
        "                            | testing purposes in order to compare results across runs\n"
        "  -h                        | This help\n"
        "  -H                        | This help plus some information about supported protocols/risks\n"
        "  -v <1|2|3|4>              | Verbose 'unknown protocol' packet print.\n"
        "                            | 1 = verbose\n"
        "                            | 2 = very verbose\n"
        "                            | 3 = port stats\n"
        "                            | 4 = hash stats\n"
        "  -V <0-4>                  | nDPI logging level\n"
        "                            | 0 - error, 1 - trace, 2 - debug, 3 - extra debug\n"
        "                            | >3 - extra debug + log enabled for all protocols (i.e. '-u all')\n"
        "  -u all|proto|num[,...]    | Enable logging only for such protocol(s)\n"
        "                            | If this flag is present multiple times (directly, or via '-V'),\n"
        "                            | only the last instance will be considered\n"
        "  -B all|proto|num[,...]    | Disable such protocol(s). By defaul all protocols are enabled\n"
        "  -T <num>                  | Max number of TCP processed packets before giving up [default: %u]\n"
        "  -U <num>                  | Max number of UDP processed packets before giving up [default: %u]\n"
        "  -D                        | Enable DoH traffic analysis based on content (no DPI)\n"
        "  -x <domain>               | Check domain name [Test only]\n"
        "  -I                        | Ignore VLAN id for flow hash calculation\n"
        "  -A                        | Dump internal statistics (LRU caches / Patricia trees / Ahocarasick automas / ...\n"
        "  -M                        | Memory allocation stats on data-path (only by the library).\n"
        "                            | It works only on single-thread configuration\n"
        "  --openvp_heuristics       | Enable OpenVPN heuristics.\n"
        "                            | It is a shortcut to --cfg=openvpn.heuristics,0x01\n"
        "  --tls_heuristics          | Enable TLS heuristics.\n"
        "                            | It is a shortcut to --cfg=tls.heuristics,0x07\n"
        "  --cfg=proto,param,value   | Configure the specific attribute of this protocol\n"
        ,
        human_readeable_string_len,
        min_pattern_len, max_pattern_len, max_num_packets_per_flow, max_packet_payload_dissection,
        max_num_reported_top_payloads, max_num_tcp_dissected_pkts, max_num_udp_dissected_pkts);

    NDPI_PROTOCOL_BITMASK all;
    struct ndpi_detection_module_struct* ndpi_str = ndpi_init_detection_module(NULL);

    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_str, &all);

    if (_protoFilePath != NULL)
        ndpi_load_protocols_file(ndpi_str, _protoFilePath);

    ndpi_finalize_initialization(ndpi_str);

    printf("\nProtocols configuration parameters:\n");
    ndpi_dump_config(ndpi_str, stdout);

#ifndef WIN32
    printf("\nExcap (wireshark) options:\n"
        "  --extcap-interfaces\n"
        "  --extcap-version\n"
        "  --extcap-dlts\n"
        "  --extcap-interface <name>\n"
        "  --extcap-config\n"
        "  --capture\n"
        "  --extcap-capture-filter <filter>\n"
        "  --fifo <path to file or pipe>\n"
        "  --ndpi-proto-filter <protocol>\n"
    );
#endif

    if (long_help) {
        printf("\n\n"
            "Size of nDPI Flow structure:      %u\n"
            "Size of nDPI Flow protocol union: %zu\n",
            ndpi_detection_get_sizeof_ndpi_flow_struct(),
            sizeof(((struct ndpi_flow_struct*)0)->protos));

        printf("\n\nnDPI supported protocols:\n");
        printf("%3s %8s %-22s %-10s %-8s %-12s %-18s %-31s %-31s \n",
            "Id", "Userd-id", "Protocol", "Layer_4", "Nw_Proto", "Breed", "Category", "Def UDP Port/s", "Def TCP Port/s");
        num_threads = 1;

        ndpi_dump_protocols(ndpi_str, stdout);

        printf("\n\nnDPI supported risks:\n");
        ndpi_dump_risks_score(stdout);
    }

    ndpi_exit_detection_module(ndpi_str);

    exit(!long_help);
}


#define OPTLONG_VALUE_CFG		3000
#define OPTLONG_VALUE_OPENVPN_HEURISTICS	3001
#define OPTLONG_VALUE_TLS_HEURISTICS		3002

static struct option longopts[] = {
  /* mandatory extcap options */
  { "extcap-interfaces", no_argument, NULL, '0'},
  { "extcap-version", optional_argument, NULL, '1'},
  { "extcap-dlts", no_argument, NULL, '2'},
  { "extcap-interface", required_argument, NULL, '3'},
  { "extcap-config", no_argument, NULL, '4'},
  { "capture", no_argument, NULL, '5'},
  { "extcap-capture-filter", required_argument, NULL, '6'},
  { "fifo", required_argument, NULL, '7'},
  { "ndpi-proto-filter", required_argument, NULL, '9'},

  /* ndpiReader options */
  { "enable-protocol-guess", no_argument, NULL, 'd'},
  { "categories", required_argument, NULL, 'c'},
  { "csv-dump", required_argument, NULL, 'C'},
  { "interface", required_argument, NULL, 'i'},
  { "filter", required_argument, NULL, 'f'},
  { "flow-stats", required_argument, NULL, 'F'},
  { "cpu-bind", required_argument, NULL, 'g'},
  { "load-categories", required_argument, NULL, 'G'},
  { "loops", required_argument, NULL, 'l'},
  { "num-threads", required_argument, NULL, 'n'},
  { "address-cache-dump", required_argument, NULL, 'N'},
  { "ignore-vlanid", no_argument, NULL, 'I'},

  { "protos", required_argument, NULL, 'p'},
  { "capture-duration", required_argument, NULL, 's'},
  { "decode-tunnels", no_argument, NULL, 't'},
  { "revision", no_argument, NULL, 'r'},
  { "verbose", required_argument, NULL, 'v'},
  { "version", no_argument, NULL, 'r'},
  { "ndpi-log-level", required_argument, NULL, 'V'},
  { "dbg-proto", required_argument, NULL, 'u'},
  { "help", no_argument, NULL, 'h'},
  { "long-help", no_argument, NULL, 'H'},
  { "serialization-outfile", required_argument, NULL, 'k'},
  { "serialization-format", required_argument, NULL, 'K'},
  { "payload-analysis", required_argument, NULL, 'P'},
  { "result-path", required_argument, NULL, 'w'},
  { "quiet", no_argument, NULL, 'q'},

  { "cfg", required_argument, NULL, OPTLONG_VALUE_CFG},
  { "openvpn_heuristics", no_argument, NULL, OPTLONG_VALUE_OPENVPN_HEURISTICS},
  { "tls_heuristics", no_argument, NULL, OPTLONG_VALUE_TLS_HEURISTICS},

  {0, 0, 0, 0}
};

/* ********************************** */

void extcap_interfaces() {
    printf("extcap {version=%s}{help=https://github.com/ntop/nDPI/tree/dev/wireshark}\n", ndpi_revision());
    printf("interface {value=ndpi}{display=nDPI interface}\n");

    extcap_exit = 1;
}

/* ********************************** */

void extcap_dlts() {
    u_int dlts_number = DLT_EN10MB;

    printf("dlt {number=%u}{name=%s}{display=%s}\n", dlts_number, "ndpi", "nDPI Interface");
    extcap_exit = 1;
}

/* ********************************** */

struct ndpi_proto_sorter {
    int id;
    char name[32];
};

/* ********************************** */

int cmpProto(const void* _a, const void* _b) {
    struct ndpi_proto_sorter* a = (struct ndpi_proto_sorter*)_a;
    struct ndpi_proto_sorter* b = (struct ndpi_proto_sorter*)_b;

    return(strcmp(a->name, b->name));
}

/* ********************************** */

void extcap_config() {
    int argidx = 0;

    struct ndpi_proto_sorter* protos;
    u_int ndpi_num_supported_protocols;
    int i;
    ndpi_proto_defaults_t* proto_defaults;
    NDPI_PROTOCOL_BITMASK all;
    struct ndpi_detection_module_struct* ndpi_str = ndpi_init_detection_module(NULL);

    if (!ndpi_str) exit(0);

    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_str, &all);

    ndpi_finalize_initialization(ndpi_str);

    ndpi_num_supported_protocols = ndpi_get_ndpi_num_supported_protocols(ndpi_str);
    proto_defaults = ndpi_get_proto_defaults(ndpi_str);

    /* -i <interface> */
    printf("arg {number=%d}{call=-i}{display=Capture Interface}{type=string}{group=Live Capture}"
        "{tooltip=The interface name}\n", argidx++);

    printf("arg {number=%d}{call=-i}{display=Pcap File to Analyze}{type=fileselect}{mustexist=true}{group=Pcap}"
        "{tooltip=The pcap file to analyze (if the interface is unspecified)}\n", argidx++);


    protos = (struct ndpi_proto_sorter*)ndpi_malloc(sizeof(struct ndpi_proto_sorter) * ndpi_num_supported_protocols);
    if (!protos) exit(0);

    printf("arg {number=%d}{call=--ndpi-proto-filter}{display=nDPI Protocol Filter}{type=selector}{group=Options}"
        "{tooltip=nDPI Protocol to be filtered}\n", argidx);

    printf("value {arg=%d}{value=%d}{display=%s}{default=true}\n", argidx, (u_int32_t)-1, "No nDPI filtering");

    for (i = 0; i < (int)ndpi_num_supported_protocols; i++) {
        protos[i].id = i;
        ndpi_snprintf(protos[i].name, sizeof(protos[i].name), "%s", proto_defaults[i].protoName);
    }

    qsort(protos, ndpi_num_supported_protocols, sizeof(struct ndpi_proto_sorter), cmpProto);

    for (i = 0; i < (int)ndpi_num_supported_protocols; i++)
        printf("value {arg=%d}{value=%d}{display=%s (%d)}{default=false}{enabled=true}\n", argidx, protos[i].id,
            protos[i].name, protos[i].id);

    ndpi_free(protos);
    argidx++;

    printf("arg {number=%d}{call=--openvp_heuristics}{display=Enable Obfuscated OpenVPN heuristics}"
        "{tooltip=Enable Obfuscated OpenVPN heuristics}{type=boolflag}{group=Options}\n", argidx++);
    printf("arg {number=%d}{call=--tls_heuristics}{display=Enable Obfuscated TLS heuristics}"
        "{tooltip=Enable Obfuscated TLS heuristics}{type=boolflag}{group=Options}\n", argidx++);

    ndpi_exit_detection_module(ndpi_str);

    extcap_exit = 1;
}

/* ********************************** */

void extcap_capture(int datalink_type) {
#ifdef DEBUG_TRACE
    if (trace_fp) fprintf(trace_fp, " #### %s #### \n", __FUNCTION__);
#endif

    if ((extcap_fifo_h = pcap_open_dead(datalink_type, 16384 /* MTU */)) == NULL) {
        fprintf(stderr, "Error pcap_open_dead");

#ifdef DEBUG_TRACE
        if (trace_fp) fprintf(trace_fp, "Error pcap_open_dead\n");
#endif
        return;
    }

    if ((extcap_dumper = pcap_dump_open(extcap_fifo_h,
        extcap_capture_fifo)) == NULL) {
        fprintf(stderr, "Unable to open the pcap dumper on %s", extcap_capture_fifo);

#ifdef DEBUG_TRACE
        if (trace_fp) fprintf(trace_fp, "Unable to open the pcap dumper on %s\n",
            extcap_capture_fifo);
#endif
        return;
    }

#ifdef DEBUG_TRACE
    if (trace_fp) fprintf(trace_fp, "Starting packet capture [%p]\n", extcap_dumper);
#endif
}

/* ********************************** */

void printCSVHeader() {
    if (!csv_fp) return;

    fprintf(csv_fp, "#flow_id|protocol|first_seen|last_seen|duration|src_ip|src_port|dst_ip|dst_port|ndpi_proto_num|ndpi_proto|proto_by_ip|server_name_sni|");
    fprintf(csv_fp, "c_to_s_pkts|c_to_s_bytes|c_to_s_goodput_bytes|s_to_c_pkts|s_to_c_bytes|s_to_c_goodput_bytes|");
    fprintf(csv_fp, "data_ratio|str_data_ratio|c_to_s_goodput_ratio|s_to_c_goodput_ratio|");

    /* IAT (Inter Arrival Time) */
    fprintf(csv_fp, "iat_flow_min|iat_flow_avg|iat_flow_max|iat_flow_stddev|");
    fprintf(csv_fp, "iat_c_to_s_min|iat_c_to_s_avg|iat_c_to_s_max|iat_c_to_s_stddev|");
    fprintf(csv_fp, "iat_s_to_c_min|iat_s_to_c_avg|iat_s_to_c_max|iat_s_to_c_stddev|");

    /* Packet Length */
    fprintf(csv_fp, "pktlen_c_to_s_min|pktlen_c_to_s_avg|pktlen_c_to_s_max|pktlen_c_to_s_stddev|");
    fprintf(csv_fp, "pktlen_s_to_c_min|pktlen_s_to_c_avg|pktlen_s_to_c_max|pktlen_s_to_c_stddev|");

    /* TCP flags */
    fprintf(csv_fp, "cwr|ece|urg|ack|psh|rst|syn|fin|");

    fprintf(csv_fp, "c_to_s_cwr|c_to_s_ece|c_to_s_urg|c_to_s_ack|c_to_s_psh|c_to_s_rst|c_to_s_syn|c_to_s_fin|");

    fprintf(csv_fp, "s_to_c_cwr|s_to_c_ece|s_to_c_urg|s_to_c_ack|s_to_c_psh|s_to_c_rst|s_to_c_syn|s_to_c_fin|");

    /* TCP window */
    fprintf(csv_fp, "c_to_s_init_win|s_to_c_init_win|");

    /* Flow info */
    fprintf(csv_fp, "server_info|");
    fprintf(csv_fp, "tls_version|quic_version|ja3c|tls_client_unsafe|");
    fprintf(csv_fp, "ja3s|tls_server_unsafe|");
    fprintf(csv_fp, "advertised_alpns|negotiated_alpn|tls_supported_versions|");
#if 0
    fprintf(csv_fp, "tls_issuerDN|tls_subjectDN|");
#endif
    fprintf(csv_fp, "ssh_client_hassh|ssh_server_hassh|flow_info|plen_bins|http_user_agent");

    if (enable_flow_stats) {
        fprintf(csv_fp, "|byte_dist_mean|byte_dist_std|entropy|total_entropy");
    }

    fprintf(csv_fp, "\n");
}

static int parse_three_strings(char* param, char** s1, char** s2, char** s3)
{
    char* saveptr, * tmp_str, * s1_str, * s2_str = NULL, * s3_str;
    int num_commas;
    unsigned int i;

    tmp_str = ndpi_strdup(param);
    if (tmp_str) {

      /* First parameter might be missing */
        num_commas = 0;
        for (i = 0; i < strlen(tmp_str); i++) {
            if (tmp_str[i] == ',')
                num_commas++;
        }

        if (num_commas == 1) {
            s1_str = NULL;
            s2_str = strtok_r(tmp_str, ",", &saveptr);
        }
        else if (num_commas == 2) {
            s1_str = strtok_r(tmp_str, ",", &saveptr);
            if (s1_str) {
                s2_str = strtok_r(NULL, ",", &saveptr);
            }
        }
        else {
            ndpi_free(tmp_str);
            return -1;
        }

        if (s2_str) {
            s3_str = strtok_r(NULL, ",", &saveptr);
            if (s3_str) {
                *s1 = ndpi_strdup(s1_str);
                *s2 = ndpi_strdup(s2_str);
                *s3 = ndpi_strdup(s3_str);
                ndpi_free(tmp_str);
                if (!s1 || !s2 || !s3) {
                    ndpi_free(s1);
                    ndpi_free(s2);
                    ndpi_free(s3);
                    return -1;
                }
                return 0;
            }
        }
    }
    ndpi_free(tmp_str);
    return -1;
}

int reader_add_cfg(char* proto, char* param, char* value, int dup)
{
    if (num_cfgs >= MAX_NUM_CFGS) {
        printf("Too many parameter! [num:%d/%d]\n", num_cfgs, MAX_NUM_CFGS);
        return -1;
    }
    cfgs[num_cfgs].proto = dup ? ndpi_strdup(proto) : proto;
    cfgs[num_cfgs].param = dup ? ndpi_strdup(param) : param;
    cfgs[num_cfgs].value = dup ? ndpi_strdup(value) : value;
    num_cfgs++;
    return 0;
}

/* ********************************** */

/**
 * @brief Option parser
 */
static void parseOptions(int argc, char** argv) {
    int option_idx = 0;
    int opt;
#ifndef USE_DPDK
    char* __pcap_file = NULL;
    int thread_id;
#ifdef __linux__
    char* bind_mask = NULL;
    u_int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
#endif
#endif
    char* s1, * s2, * s3;

#ifdef USE_DPDK
    {
        int ret = rte_eal_init(argc, argv);

        if (ret < 0)
            rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

        argc -= ret, argv += ret;
    }
#endif

    while ((opt = getopt_long(argc, argv,
        "a:Ab:B:e:E:c:C:dDFf:g:G:i:Ij:k:K:S:hHp:pP:l:r:Rs:tu:v:V:n:rp:x:X:w:q0123:456:7:89:m:MN:T:U:",
        longopts, &option_idx)) != EOF) {
#ifdef DEBUG_TRACE
        if (trace_fp) fprintf(trace_fp, " #### Handling option -%c [%s] #### \n", opt, optarg ? optarg : "");
#endif

        switch (opt) {
        case 'a':
            ndpi_generate_options(atoi(optarg), stdout);
            exit(0);

        case 'A':
            dump_internal_stats = 1;
            break;

        case 'b':
            if ((num_bin_clusters = atoi(optarg)) > 32)
                num_bin_clusters = 32;
            break;

        case 'd':
            enable_protocol_guess = 0;
            if (reader_add_cfg(NULL, "dpi.guess_on_giveup", "0", 1) == 1) {
                printf("Invalid parameter [%s] [num:%d/%d]\n", optarg, num_cfgs, MAX_NUM_CFGS);
                exit(1);
            }
            break;

        case 'D':
            enable_doh_dot_detection = 1;
            break;

        case 'e':
            human_readeable_string_len = atoi(optarg);
            break;

        case 'E':
            errno = 0;
            if ((fingerprint_fp = fopen(optarg, "w")) == NULL) {
                printf("Unable to write on fingerprint file %s: %s\n", optarg, strerror(errno));
                exit(1);
            }

            if (reader_add_cfg("tls", "metadata.ja4r_fingerprint", "1", 1) == -1) {
                printf("Unable to enable JA4r fingerprints\n");
                exit(1);
            }

            do_load_lists = true;
            break;

        case 'i':
        case '3':
            _pcap_file[0] = optarg;
            break;

        case 'I':
            ignore_vlanid = 1;
            break;

        case 'j':
            _maliciousJA3Path = optarg;
            break;

        case 'S':
            _maliciousSHA1Path = optarg;
            break;

        case 'm':
            pcap_analysis_duration = atol(optarg);
            break;

        case 'f':
        case '6':
            bpfFilter = optarg;
            break;

#ifndef USE_DPDK
#ifdef __linux__
        case 'g':
            bind_mask = optarg;
            break;
#endif
#endif

        case 'G':
            _categoriesDirPath = optarg;
            break;

        case 'l':
            num_loops = atoi(optarg);
            break;

        case 'n':
            num_threads = atoi(optarg);
            break;

        case 'N':
            addr_dump_path = optarg;
            break;

        case 'p':
            _protoFilePath = optarg;
            break;

        case 'c':
            _customCategoryFilePath = optarg;
            break;

        case 'C':
            errno = 0;
            if ((csv_fp = fopen(optarg, "w+")) == NULL)
            {
                printf("Unable to write on CSV file %s: %s\n", optarg, strerror(errno));
                exit(1);
            }
            break;

        case 'r':
            _riskyDomainFilePath = optarg;
            break;

        case 'R':
            enable_realtime_output = 1;
            break;

        case 's':
            capture_for = atoi(optarg);
            capture_until = capture_for + time(NULL);
            break;

        case 't':
            decode_tunnels = 1;
            break;

        case 'v':
            verbose = atoi(optarg);
            break;

        case 'V':
        {
            char buf[12];
            int log_level;
            const char* errstrp;

            /* (Internals) log levels are 0-3, but ndpiReader allows 0-4, where with 4
                we also enable all protocols */
            log_level = ndpi_strtonum(optarg, NDPI_LOG_ERROR, NDPI_LOG_DEBUG_EXTRA + 1, &errstrp, 10);
            if (errstrp != NULL) {
                printf("Invalid log level %s: %s\n", optarg, errstrp);
                exit(1);
            }
            if (log_level > NDPI_LOG_DEBUG_EXTRA) {
                log_level = NDPI_LOG_DEBUG_EXTRA;
                if (reader_add_cfg("all", "log", "enable", 1) == 1) {
                    printf("Invalid cfg [num:%d/%d]\n", num_cfgs, MAX_NUM_CFGS);
                    exit(1);
                }
            }
            snprintf(buf, sizeof(buf), "%d", log_level);
            if (reader_add_cfg(NULL, "log.level", buf, 1) == 1) {
                printf("Invalid log level [%s] [num:%d/%d]\n", buf, num_cfgs, MAX_NUM_CFGS);
                exit(1);
            }
            reader_log_level = log_level;
            break;
        }

        case 'u':
        {
            char* n;
            char* str = ndpi_strdup(optarg);
            int inverted_logic;

            /* Reset any previous call to this knob */
            if (reader_add_cfg("all", "log", "disable", 1) == 1) {
                printf("Invalid cfg [num:%d/%d]\n", num_cfgs, MAX_NUM_CFGS);
                exit(1);
            }

            for (n = strtok(str, ","); n && *n; n = strtok(NULL, ",")) {
                inverted_logic = 0;
                if (*n == '-') {
                    inverted_logic = 1;
                    n++;
                }
                if (reader_add_cfg(n, "log", inverted_logic ? "disable" : "enable", 1) == 1) {
                    printf("Invalid parameter [%s] [num:%d/%d]\n", n, num_cfgs, MAX_NUM_CFGS);
                    exit(1);
                }
            }
            ndpi_free(str);
            break;
        }

        case 'B':
            ndpi_free(_disabled_protocols);
            _disabled_protocols = ndpi_strdup(optarg);
            break;

        case 'h':
            help(0);
            break;

        case 'H':
            help(1);
            break;

        case 'F':
            enable_flow_stats = 1;
            break;

        case 'P':
        {
            int _min_pattern_len, _max_pattern_len,
                _max_num_packets_per_flow, _max_packet_payload_dissection,
                _max_num_reported_top_payloads;

            enable_payload_analyzer = 1;
            if (sscanf(optarg, "%d:%d:%d:%d:%d", &_min_pattern_len, &_max_pattern_len,
                &_max_num_packets_per_flow,
                &_max_packet_payload_dissection,
                &_max_num_reported_top_payloads) == 5) {
                min_pattern_len = _min_pattern_len, max_pattern_len = _max_pattern_len;
                max_num_packets_per_flow = _max_num_packets_per_flow, max_packet_payload_dissection = _max_packet_payload_dissection;
                max_num_reported_top_payloads = _max_num_reported_top_payloads;
                if (min_pattern_len > max_pattern_len) min_pattern_len = max_pattern_len;
                if (min_pattern_len < 2)               min_pattern_len = 2;
                if (max_pattern_len > 16)              max_pattern_len = 16;
                if (max_num_packets_per_flow == 0)     max_num_packets_per_flow = 1;
                if (max_packet_payload_dissection < 4) max_packet_payload_dissection = 4;
                if (max_num_reported_top_payloads == 0) max_num_reported_top_payloads = 1;
            }
            else {
                printf("Invalid -P format. Ignored\n");
                help(0);
            }
        }
        break;

        case 'M':
            enable_malloc_bins = 1;
            ndpi_init_bin(&malloc_bins, ndpi_bin_family64, max_malloc_bins);
            break;

        case 'k':
            errno = 0;
            if ((serialization_fp = fopen(optarg, "w")) == NULL)
            {
                printf("Unable to write on serialization file %s: %s\n", optarg, strerror(errno));
                exit(1);
            }
            break;

        case 'K':
            if (strcasecmp(optarg, "tlv") == 0 && strlen(optarg) == 3)
            {
                serialization_format = ndpi_serialization_format_tlv;
            }
            else if (strcasecmp(optarg, "csv") == 0 && strlen(optarg) == 3)
            {
                serialization_format = ndpi_serialization_format_csv;
            }
            else if (strcasecmp(optarg, "json") == 0 && strlen(optarg) == 4)
            {
                serialization_format = ndpi_serialization_format_json;
            }
            else {
                printf("Unknown serialization format. Valid values are: tlv,csv,json\n");
                exit(1);
            }
            break;

        case 'w':
            results_path = ndpi_strdup(optarg);
            if ((results_file = fopen(results_path, "w")) == NULL) {
                printf("Unable to write in file %s: quitting\n", results_path);
                exit(1);
            }
            break;

        case 'q':
            quiet_mode = 1;
            if (reader_add_cfg(NULL, "log.level", "0", 1) == 1) {
                printf("Invalid cfg [num:%d/%d]\n", num_cfgs, MAX_NUM_CFGS);
                exit(1);
            }
            reader_log_level = 0;
            break;

        case OPTLONG_VALUE_OPENVPN_HEURISTICS:
            if (reader_add_cfg("openvpn", "dpi.heuristics", "0x01", 1) == 1) {
                printf("Invalid cfg [num:%d/%d]\n", num_cfgs, MAX_NUM_CFGS);
                exit(1);
            }
            break;

        case OPTLONG_VALUE_TLS_HEURISTICS:
            if (reader_add_cfg("tls", "dpi.heuristics", "0x07", 1) == 1) {
                printf("Invalid cfg [num:%d/%d]\n", num_cfgs, MAX_NUM_CFGS);
                exit(1);
            }
            break;

            /* Extcap */
        case '0':
            extcap_interfaces();
            break;

        case '1':
            printf("extcap {version=%s}\n", ndpi_revision());
            break;

        case '2':
            extcap_dlts();
            break;

        case '4':
            extcap_config();
            break;

#ifndef USE_DPDK
        case '5':
            do_extcap_capture = 1;
            break;
#endif

        case '7':
            extcap_capture_fifo = ndpi_strdup(optarg);
            break;

        case '9':
        {
            struct ndpi_detection_module_struct* ndpi_str = ndpi_init_detection_module(NULL);
            NDPI_PROTOCOL_BITMASK all;

            NDPI_BITMASK_SET_ALL(all);
            ndpi_set_protocol_detection_bitmask2(ndpi_str, &all);
            ndpi_finalize_initialization(ndpi_str);

            extcap_packet_filter = ndpi_get_proto_by_name(ndpi_str, optarg);
            if (extcap_packet_filter == NDPI_PROTOCOL_UNKNOWN) extcap_packet_filter = atoi(optarg);

            ndpi_exit_detection_module(ndpi_str);
            break;
        }

        case 'T':
            max_num_tcp_dissected_pkts = atoi(optarg);
            /* If we enable that, allow at least 3WHS + 1 "real" packet */
            if (max_num_tcp_dissected_pkts != 0 && max_num_tcp_dissected_pkts < 4) max_num_tcp_dissected_pkts = 4;
            break;

        case 'x':
            domain_to_check = optarg;
            break;

        case 'X':
            ip_port_to_check = optarg;
            break;

        case 'U':
            max_num_udp_dissected_pkts = atoi(optarg);
            break;

        case OPTLONG_VALUE_CFG:
            if (parse_three_strings(optarg, &s1, &s2, &s3) == -1 ||
                reader_add_cfg(s1, s2, s3, 0) == -1) {
                printf("Invalid parameter [%s] [num:%d/%d]\n", optarg, num_cfgs, MAX_NUM_CFGS);
                exit(1);
            }
            break;

        default:
#ifdef DEBUG_TRACE
            if (trace_fp) fprintf(trace_fp, " #### Unknown option -%c: skipping it #### \n", opt);
#endif

            help(0);
            break;
        }
    }

    if (serialization_fp == NULL && serialization_format != ndpi_serialization_format_unknown)
    {
        printf("Serializing detection results to a file requires command line arguments `-k'\n");
        exit(1);
    }
    if (serialization_fp != NULL && serialization_format == ndpi_serialization_format_unknown)
    {
        serialization_format = ndpi_serialization_format_json;
    }

    if (extcap_exit)
        exit(0);

    printCSVHeader();

#ifndef USE_DPDK
    if (do_extcap_capture) {
        quiet_mode = 1;
    }

    if (!domain_to_check && !ip_port_to_check) {
        if (_pcap_file[0] == NULL)
            help(0);

        if (strchr(_pcap_file[0], ',')) { /* multiple ingress interfaces */
            num_threads = 0;               /* setting number of threads = number of interfaces */
            __pcap_file = strtok(_pcap_file[0], ",");
            while (__pcap_file != NULL && num_threads < MAX_NUM_READER_THREADS) {
                _pcap_file[num_threads++] = __pcap_file;
                __pcap_file = strtok(NULL, ",");
            }
        }
        else {
            if (num_threads > MAX_NUM_READER_THREADS) num_threads = MAX_NUM_READER_THREADS;
            for (thread_id = 1; thread_id < num_threads; thread_id++)
                _pcap_file[thread_id] = _pcap_file[0];
        }

        if (num_threads > 1 && enable_malloc_bins == 1)
        {
            printf("Memory profiling ('-M') is incompatible with multi-thread enviroment");
            exit(1);
        }
    }

#ifdef __linux__
#ifndef USE_DPDK
    for (thread_id = 0; thread_id < num_threads; thread_id++)
        core_affinity[thread_id] = -1;

    if (num_cores > 1 && bind_mask != NULL) {
        char* core_id = strtok(bind_mask, ":");
        thread_id = 0;

        while (core_id != NULL && thread_id < num_threads) {
            core_affinity[thread_id++] = atoi(core_id) % num_cores;
            core_id = strtok(NULL, ":");
        }
    }
#endif
#endif
#endif
}

/* *********************************************** */

/**
 * @brief Idle Scan Walker
 */
static void node_idle_scan_walker(const void* node, ndpi_VISIT which, int depth, void* user_data) {
    struct ndpi_flow_info* flow = *(struct ndpi_flow_info**)node;
    u_int16_t thread_id = *((u_int16_t*)user_data);

    if (ndpi_thread_info[thread_id].num_idle_flows == IDLE_SCAN_BUDGET) /* TODO optimise with a budget-based walk */
        return;

    if ((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
        if (flow->last_seen_ms + MAX_IDLE_TIME < ndpi_thread_info[thread_id].workflow->last_time) {

          /* update stats */
            node_proto_guess_walker(node, which, depth, user_data);
            if (verbose == 3)
                port_stats_walker(node, which, depth, user_data);

            if ((flow->detected_protocol.proto.app_protocol == NDPI_PROTOCOL_UNKNOWN) && !undetected_flows_deleted)
                undetected_flows_deleted = 1;

            ndpi_flow_info_free_data(flow);
            ndpi_thread_info[thread_id].workflow->stats.ndpi_flow_count--;

            /* adding to a queue (we can't delete it from the tree inline ) */
            ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows++] = flow;
        }
    }
}

/* *********************************************** */

#if 0
/**
 * @brief Print debug
 */
static void debug_printf(u_int32_t protocol, void* id_struct,
    ndpi_log_level_t log_level,
    const char* format, ...) {
    va_list va_ap;
    struct tm result;

    if (log_level <= nDPI_LogLevel) {
        char buf[8192], out_buf[8192];
        char theDate[32];
        const char* extra_msg = "";
        time_t theTime = time(NULL);

        va_start(va_ap, format);

        if (log_level == NDPI_LOG_ERROR)
            extra_msg = "ERROR: ";
        else if (log_level == NDPI_LOG_TRACE)
            extra_msg = "TRACE: ";
        else
            extra_msg = "DEBUG: ";

        memset(buf, 0, sizeof(buf));
        strftime(theDate, 32, "%d/%b/%Y %H:%M:%S", localtime_r(&theTime, &result));
        ndpi_snprintf(buf, sizeof(buf) - 1, format, va_ap);

        ndpi_snprintf(out_buf, sizeof(out_buf), "%s %s%s", theDate, extra_msg, buf);
        printf("%s", out_buf);
        fflush(stdout);
    }

    va_end(va_ap);
}
#endif

/* *********************************************** */

static int is_realtime_protocol(ndpi_protocol proto)
{
    static u_int16_t const realtime_protos[] = {
      NDPI_PROTOCOL_YOUTUBE,
      NDPI_PROTOCOL_YOUTUBE_UPLOAD,
      NDPI_PROTOCOL_TIKTOK,
      NDPI_PROTOCOL_GOOGLE,
      NDPI_PROTOCOL_GOOGLE_CLASSROOM,
      NDPI_PROTOCOL_GOOGLE_CLOUD,
      NDPI_PROTOCOL_GOOGLE_DOCS,
      NDPI_PROTOCOL_GOOGLE_DRIVE,
      NDPI_PROTOCOL_GOOGLE_MAPS,
      NDPI_PROTOCOL_GOOGLE_SERVICES
    };
    u_int16_t i;

    for (i = 0; i < NDPI_ARRAY_LENGTH(realtime_protos); i++) {
        if (proto.proto.app_protocol == realtime_protos[i]
            || proto.proto.master_protocol == realtime_protos[i])
        {
            return 1;
        }
    }

    return 0;
}

static void dump_realtime_protocol(struct ndpi_workflow* workflow, struct ndpi_flow_info* flow)
{
    FILE* out = results_file ? results_file : stdout;
    char srcip[70], dstip[70];
    char ip_proto[64], app_name[64];
    char date[64];
    int ret = is_realtime_protocol(flow->detected_protocol);
    time_t firsttime = flow->first_seen_ms;
    struct tm result;

    if (ndpi_gmtime_r(&firsttime, &result) != NULL)
    {
        strftime(date, sizeof(date), "%d.%m.%y %H:%M:%S", &result);
    }
    else {
        snprintf(date, sizeof(date), "%s", "Unknown");
    }

    if (flow->ip_version == 4) {
        inet_ntop(AF_INET, &flow->src_ip, srcip, sizeof(srcip));
        inet_ntop(AF_INET, &flow->dst_ip, dstip, sizeof(dstip));
    }
    else {
        snprintf(srcip, sizeof(srcip), "[%s]", flow->src_name);
        snprintf(dstip, sizeof(dstip), "[%s]", flow->dst_name);
    }

    ndpi_protocol2name(workflow->ndpi_struct, flow->detected_protocol, app_name, sizeof(app_name));

    if (ret == 1) {
        fprintf(out, "Detected Realtime protocol %s --> [%s] %s:%d <--> %s:%d app=%s <%s>\n",
            date, ndpi_get_ip_proto_name(flow->protocol, ip_proto, sizeof(ip_proto)),
            srcip, ntohs(flow->src_port), dstip, ntohs(flow->dst_port),
            app_name, flow->human_readeable_string_buffer);
    }
}

static void on_protocol_discovered(struct ndpi_workflow* workflow,
    struct ndpi_flow_info* flow,
    void* userdata)
{
    (void)userdata;
    if (enable_realtime_output != 0)
        dump_realtime_protocol(workflow, flow);
}

/* *********************************************** */

/**
 * @brief Setup for detection begin
 */
static void setupDetection(u_int16_t thread_id, pcap_t* pcap_handle,
    struct ndpi_global_context* g_ctx) {
    NDPI_PROTOCOL_BITMASK enabled_bitmask;
    struct ndpi_workflow_prefs prefs;
    int i, ret;
    ndpi_cfg_error rc;

    memset(&prefs, 0, sizeof(prefs));
    prefs.decode_tunnels = decode_tunnels;
    prefs.num_roots = NUM_ROOTS;
    prefs.max_ndpi_flows = MAX_NDPI_FLOWS;
    prefs.quiet_mode = quiet_mode;
    prefs.ignore_vlanid = ignore_vlanid;

    memset(&ndpi_thread_info[thread_id], 0, sizeof(ndpi_thread_info[thread_id]));
    ndpi_thread_info[thread_id].workflow = ndpi_workflow_init(&prefs, pcap_handle, 1,
        serialization_format, g_ctx);

/* Protocols to enable/disable. Default: everything is enabled */
    NDPI_BITMASK_SET_ALL(enabled_bitmask);
    if (_disabled_protocols != NULL) {
        if (parse_proto_name_list(_disabled_protocols, &enabled_bitmask, 1))
            exit(-1);
    }

    if (_categoriesDirPath) {
        int failed_files = ndpi_load_categories_dir(ndpi_thread_info[thread_id].workflow->ndpi_struct, _categoriesDirPath);
        if (failed_files < 0) {
            fprintf(stderr, "Failed to parse all *.list files in: %s\n", _categoriesDirPath);
            exit(-1);
        }
    }

    if (_riskyDomainFilePath)
        ndpi_load_risk_domain_file(ndpi_thread_info[thread_id].workflow->ndpi_struct, _riskyDomainFilePath);

    if (_maliciousJA3Path)
        ndpi_load_malicious_ja3_file(ndpi_thread_info[thread_id].workflow->ndpi_struct, _maliciousJA3Path);

    if (_maliciousSHA1Path)
        ndpi_load_malicious_sha1_file(ndpi_thread_info[thread_id].workflow->ndpi_struct, _maliciousSHA1Path);

    if (_customCategoryFilePath) {
        char* label = strrchr(_customCategoryFilePath, '/');

        if (label != NULL)
            label = &label[1];
        else
            label = _customCategoryFilePath;

        int failed_lines = ndpi_load_categories_file(ndpi_thread_info[thread_id].workflow->ndpi_struct, _customCategoryFilePath, label);
        if (failed_lines < 0) {
            fprintf(stderr, "Failed to parse custom categories file: %s\n", _customCategoryFilePath);
            exit(-1);
        }
    }

    ndpi_thread_info[thread_id].workflow->g_ctx = g_ctx;

    ndpi_workflow_set_flow_callback(ndpi_thread_info[thread_id].workflow,
        on_protocol_discovered, NULL);

/* Make sure to load lists before finalizing the initialization */
    ndpi_set_protocol_detection_bitmask2(ndpi_thread_info[thread_id].workflow->ndpi_struct, &enabled_bitmask);

    if (_protoFilePath != NULL)
        ndpi_load_protocols_file(ndpi_thread_info[thread_id].workflow->ndpi_struct, _protoFilePath);

    ndpi_set_config(ndpi_thread_info[thread_id].workflow->ndpi_struct, NULL, "tcp_ack_payload_heuristic", "enable");

    for (i = 0; i < num_cfgs; i++) {
        rc = ndpi_set_config(ndpi_thread_info[thread_id].workflow->ndpi_struct,
            cfgs[i].proto, cfgs[i].param, cfgs[i].value);
        if (rc != NDPI_CFG_OK) {
            fprintf(stderr, "Error setting config [%s][%s][%s]: %s (%d)\n",
                (cfgs[i].proto != NULL ? cfgs[i].proto : ""),
                cfgs[i].param, cfgs[i].value, ndpi_cfg_error2string(rc), rc);
            exit(-1);
        }
    }

    if (enable_doh_dot_detection)
        ndpi_set_config(ndpi_thread_info[thread_id].workflow->ndpi_struct, "tls", "application_blocks_tracking", "enable");

    if (addr_dump_path != NULL)
        ndpi_cache_address_restore(ndpi_thread_info[thread_id].workflow->ndpi_struct, addr_dump_path, 0);

    ret = ndpi_finalize_initialization(ndpi_thread_info[thread_id].workflow->ndpi_struct);
    if (ret != 0) {
        fprintf(stderr, "Error ndpi_finalize_initialization: %d\n", ret);
        exit(-1);
    }
}

/* *********************************************** */

/**
 * @brief End of detection and free flow
 */
static void terminateDetection(u_int16_t thread_id) {
    ndpi_workflow_free(ndpi_thread_info[thread_id].workflow);
    ndpi_thread_info[thread_id].workflow = NULL;
}

/* *********************************************** */

/**
 * @brief Force a pcap_dispatch() or pcap_loop() call to return
 */
static void breakPcapLoop(u_int16_t thread_id) {
#ifdef USE_DPDK
    dpdk_run_capture = 0;
#else
    if (ndpi_thread_info[thread_id].workflow->pcap_handle != NULL) {
        pcap_breakloop(ndpi_thread_info[thread_id].workflow->pcap_handle);
    }
#endif
}

/**
 * @brief Sigproc is executed for each packet in the pcap file
 */
void sigproc(int sig) {

    static int called = 0;
    int thread_id;

    (void)sig;

    if (called) return; else called = 1;
    shutdown_app = 1;

    for (thread_id = 0; thread_id < num_threads; thread_id++)
        breakPcapLoop(thread_id);
}


#ifndef USE_DPDK

/**
 * @brief Get the next pcap file from a passed playlist
 */
static int getNextPcapFileFromPlaylist(u_int16_t thread_id, char filename[], u_int32_t filename_len) {

    if (playlist_fp[thread_id] == NULL) {
        if ((playlist_fp[thread_id] = fopen(_pcap_file[thread_id], "r")) == NULL)
            return -1;
    }

next_line:
    if (fgets(filename, filename_len, playlist_fp[thread_id])) {
        int l = strlen(filename);
        if (filename[0] == '\0' || filename[0] == '#') goto next_line;
        if (filename[l - 1] == '\n') filename[l - 1] = '\0';
        return 0;
    }
    else {
        fclose(playlist_fp[thread_id]);
        playlist_fp[thread_id] = NULL;
        return -1;
    }
}

/**
 * @brief Configure the pcap handle
 */
static void configurePcapHandle(pcap_t* pcap_handle) {

    if (bpfFilter != NULL) {

        if (!bpf_cfilter) {
            if (pcap_compile(pcap_handle, &bpf_code, bpfFilter, 1, 0xFFFFFF00) < 0) {
                printf("pcap_compile error: '%s'\n", pcap_geterr(pcap_handle));
                return;
            }
            bpf_cfilter = &bpf_code;
        }
        if (pcap_setfilter(pcap_handle, bpf_cfilter) < 0) {
            printf("pcap_setfilter error: '%s'\n", pcap_geterr(pcap_handle));
        }
        else {
            printf("Successfully set BPF filter to '%s'\n", bpfFilter);
        }
    }
}

#endif

/**
 * @brief Open a pcap file or a specified device - Always returns a valid pcap_t
 */
static pcap_t* openPcapFileOrDevice(u_int16_t thread_id, const u_char* pcap_file) {
#ifndef USE_DPDK
    u_int snaplen = 1536;
    int promisc = 1;
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];
#endif
    pcap_t* pcap_handle = NULL;

    /* trying to open a live interface */
#ifdef USE_DPDK
    struct rte_mempool* mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
        MBUF_CACHE_SIZE, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id());

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool: are hugepages ok?\n");

    if (dpdk_port_init(dpdk_port_id, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "DPDK: Cannot init port %u: please see README.dpdk\n", dpdk_port_id);
#else
  /* Trying to open the interface */
    if ((pcap_handle = pcap_open_live((char*)pcap_file, snaplen,
        promisc, 500, pcap_error_buffer)) == NULL) {
        capture_for = capture_until = 0;

        live_capture = 0;
        num_threads = 1; /* Open pcap files in single threads mode */

        /* Trying to open a pcap file */
        if ((pcap_handle = pcap_open_offline((char*)pcap_file, pcap_error_buffer)) == NULL) {
            char filename[256] = { 0 };

            if (strstr((char*)pcap_file, (char*)".pcap"))
                printf("ERROR: could not open pcap file: %s\n", pcap_error_buffer);

                  /* Trying to open as a playlist as last attempt */
            else if ((getNextPcapFileFromPlaylist(thread_id, filename, sizeof(filename)) != 0)
                || ((pcap_handle = pcap_open_offline(filename, pcap_error_buffer)) == NULL)) {
          /* This probably was a bad interface name, printing a generic error */
                printf("ERROR: could not open %s: %s\n", filename, pcap_error_buffer);
                exit(-1);
            }
            else {
                if (!quiet_mode)
                    printf("Reading packets from playlist %s...\n", pcap_file);
            }
        }
        else {
            if (!quiet_mode)
                printf("Reading packets from pcap file %s...\n", pcap_file);
        }
    }
    else {
        live_capture = 1;

        if (!quiet_mode) {
#ifdef USE_DPDK
            printf("Capturing from DPDK (port 0)...\n");
#else
            printf("Capturing live traffic from device %s...\n", pcap_file);
#endif
        }
    }

    configurePcapHandle(pcap_handle);
#endif /* !DPDK */

    if (capture_for > 0) {
        if (!quiet_mode)
            printf("Capturing traffic up to %u seconds\n", (unsigned int)capture_for);

#ifndef WIN32
        alarm(capture_for);
        signal(SIGALRM, sigproc);
#endif
    }

    return pcap_handle;
}

/**
 * @brief Check pcap packet
 */
static void ndpi_process_packet(u_char* args,
    // _TODO: Print on this function instead

    const struct pcap_pkthdr* header,
    const u_char* packet) {
    struct ndpi_proto p;
    ndpi_risk flow_risk;
    struct ndpi_flow_info* flow;
    u_int16_t thread_id = *((u_int16_t*)args);

    /* allocate an exact size buffer to check overflows */
    uint8_t* packet_checked = ndpi_malloc(header->caplen);

    if (packet_checked == NULL) {
        return;
    }

    memcpy(packet_checked, packet, header->caplen);
    p = ndpi_workflow_process_packet(ndpi_thread_info[thread_id].workflow, header, packet_checked, &flow_risk, &flow);

    if (!pcap_start.tv_sec) pcap_start.tv_sec = header->ts.tv_sec, pcap_start.tv_usec = header->ts.tv_usec;
    pcap_end.tv_sec = header->ts.tv_sec, pcap_end.tv_usec = header->ts.tv_usec;

    /* Idle flows cleanup */
    if (live_capture) {
        if (ndpi_thread_info[thread_id].last_idle_scan_time + IDLE_SCAN_PERIOD < ndpi_thread_info[thread_id].workflow->last_time) {
          /* scan for idle flows */
            ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[ndpi_thread_info[thread_id].idle_scan_idx],
                node_idle_scan_walker, &thread_id);

             /* remove idle flows (unfortunately we cannot do this inline) */
            while (ndpi_thread_info[thread_id].num_idle_flows > 0) {
          /* search and delete the idle flow from the "ndpi_flow_root" (see struct reader thread) - here flows are the node of a b-tree */
                ndpi_tdelete(ndpi_thread_info[thread_id].idle_flows[--ndpi_thread_info[thread_id].num_idle_flows],
                    &ndpi_thread_info[thread_id].workflow->ndpi_flows_root[ndpi_thread_info[thread_id].idle_scan_idx],
                    ndpi_workflow_node_cmp);

           /* free the memory associated to idle flow in "idle_flows" - (see struct reader thread)*/
                ndpi_free_flow_info_half(ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows]);
                ndpi_free(ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows]);
            }

            if (++ndpi_thread_info[thread_id].idle_scan_idx == ndpi_thread_info[thread_id].workflow->prefs.num_roots)
                ndpi_thread_info[thread_id].idle_scan_idx = 0;

            ndpi_thread_info[thread_id].last_idle_scan_time = ndpi_thread_info[thread_id].workflow->last_time;
        }
    }

#ifdef DEBUG_TRACE
    if (trace_fp) fprintf(trace_fp, "Found %u bytes packet %u.%u\n", header->caplen, p.proto.app_protocol, p.proto.master_protocol);
#endif

    if (extcap_dumper
        && ((extcap_packet_filter == (u_int16_t)-1)
            || (p.proto.app_protocol == extcap_packet_filter)
            || (p.proto.master_protocol == extcap_packet_filter)
            )
        ) {
        struct pcap_pkthdr h;
        u_int32_t* crc, delta = sizeof(struct ndpi_packet_trailer);
        struct ndpi_packet_trailer* trailer;
        u_int16_t cli_score, srv_score;

        memcpy(&h, header, sizeof(h));

        if (extcap_add_crc)
            delta += 4; /* ethernet trailer */

        if (h.caplen > (sizeof(extcap_buf) - delta)) {
            printf("INTERNAL ERROR: caplen=%u\n", h.caplen);
            h.caplen = sizeof(extcap_buf) - delta;
        }

        trailer = (struct ndpi_packet_trailer*)&extcap_buf[h.caplen];
        memcpy(extcap_buf, packet, h.caplen);
        memset(trailer, 0, sizeof(struct ndpi_packet_trailer));
        trailer->magic = htonl(WIRESHARK_NTOP_MAGIC);
        if (flow) {
            trailer->flags = flow->current_pkt_from_client_to_server;
            trailer->flags |= (flow->detection_completed << 2);
        }
        else {
            trailer->flags = 0 | (2 << 2);
        }
        trailer->flow_risk = htonl64(flow_risk);
        trailer->flow_score = htons(ndpi_risk2score(flow_risk, &cli_score, &srv_score));
        trailer->flow_risk_info_len = ntohs(WIRESHARK_FLOW_RISK_INFO_SIZE);
        if (flow && flow->risk_str) {
            strncpy(trailer->flow_risk_info, flow->risk_str, sizeof(trailer->flow_risk_info));
        }
        trailer->flow_risk_info[sizeof(trailer->flow_risk_info) - 1] = '\0';
        trailer->proto.master_protocol = htons(p.proto.master_protocol), trailer->proto.app_protocol = htons(p.proto.app_protocol);
        ndpi_protocol2name(ndpi_thread_info[thread_id].workflow->ndpi_struct, p, trailer->name, sizeof(trailer->name));

        /* Metadata */
        /* Metadata are (all) available in `flow` only after nDPI completed its work!
           We export them only once */
        /* TODO: boundary check. Right now there is always enough room, but we should check it if we are
           going to extend the list of the metadata exported */
        trailer->metadata_len = ntohs(WIRESHARK_METADATA_SIZE);
        struct ndpi_packet_tlv* tlv = (struct ndpi_packet_tlv*)trailer->metadata;
        int tot_len = 0;
        if (flow && flow->detection_completed == 1) {
            if (flow->host_server_name[0] != '\0') {
                tlv->type = ntohs(WIRESHARK_METADATA_SERVERNAME);
                tlv->length = ntohs(sizeof(flow->host_server_name));
                memcpy(tlv->data, flow->host_server_name, sizeof(flow->host_server_name));
                /* TODO: boundary check */
                tot_len += 4 + htons(tlv->length);
                tlv = (struct ndpi_packet_tlv*)&trailer->metadata[tot_len];
            }
            if (flow->ssh_tls.ja4_client[0] != '\0') {
                tlv->type = ntohs(WIRESHARK_METADATA_JA4C);
                tlv->length = ntohs(sizeof(flow->ssh_tls.ja4_client));
                memcpy(tlv->data, flow->ssh_tls.ja4_client, sizeof(flow->ssh_tls.ja4_client));
                /* TODO: boundary check */
                tot_len += 4 + htons(tlv->length);
                tlv = (struct ndpi_packet_tlv*)&trailer->metadata[tot_len];
            }

            flow->detection_completed = 2; /* Avoid exporting metadata again.
                                              If we really want to have the metadata on Wireshark for *all*
                                              the future packets of this flow, simply remove that assignment */
        }
        /* Last: padding */
        tlv->type = 0;
        tlv->length = ntohs(WIRESHARK_METADATA_SIZE - tot_len - 4);
        /* The remaining bytes are already set to 0 */

        if (extcap_add_crc) {
            crc = (uint32_t*)&extcap_buf[h.caplen + sizeof(struct ndpi_packet_trailer)];
            *crc = ndpi_crc32((const void*)extcap_buf, h.caplen + sizeof(struct ndpi_packet_trailer), 0);
        }
        h.caplen += delta, h.len += delta;

#ifdef DEBUG_TRACE
        if (trace_fp) fprintf(trace_fp, "Dumping %u bytes packet\n", h.caplen);
#endif

        pcap_dump((u_char*)extcap_dumper, &h, (const u_char*)extcap_buf);
        pcap_dump_flush(extcap_dumper);
    }

    /* check for buffer changes */
    if (memcmp(packet, packet_checked, header->caplen) != 0)
        printf("INTERNAL ERROR: ingress packet was modified by nDPI: this should not happen [thread_id=%u, packetId=%lu, caplen=%u]\n",
            thread_id, (unsigned long)ndpi_thread_info[thread_id].workflow->stats.raw_packet_count, header->caplen);

    if ((u_int32_t)(pcap_end.tv_sec - pcap_start.tv_sec) > pcap_analysis_duration) {
        unsigned int i;
        u_int64_t processing_time_usec, setup_time_usec;

        gettimeofday(&end, NULL);
        processing_time_usec = (u_int64_t)end.tv_sec * 1000000 + end.tv_usec - ((u_int64_t)begin.tv_sec * 1000000 + begin.tv_usec);
        setup_time_usec = (u_int64_t)begin.tv_sec * 1000000 + begin.tv_usec - ((u_int64_t)startup_time.tv_sec * 1000000 + startup_time.tv_usec);

        printResults(processing_time_usec, setup_time_usec);

        for (i = 0; i < ndpi_thread_info[thread_id].workflow->prefs.num_roots; i++) {
            ndpi_tdestroy(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i], ndpi_flow_info_freer);
            ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i] = NULL;

            memset(&ndpi_thread_info[thread_id].workflow->stats, 0, sizeof(struct ndpi_stats));
        }

        if (!quiet_mode)
            printf("\n-------------------------------------------\n\n");

        memcpy(&begin, &end, sizeof(begin));
        memcpy(&pcap_start, &pcap_end, sizeof(pcap_start));
    }

    /*
      Leave the free as last statement to avoid crashes when ndpi_detection_giveup()
      is called above by printResults()
    */
    if (packet_checked) {
        ndpi_free(packet_checked);
        packet_checked = NULL;
    }
}

#ifndef USE_DPDK
/**
 * @brief Call pcap_loop() to process packets from a live capture or savefile
 */
static void runPcapLoop(u_int16_t thread_id) {
    if ((!shutdown_app) && (ndpi_thread_info[thread_id].workflow->pcap_handle != NULL)) {

        int datalink_type = pcap_datalink(ndpi_thread_info[thread_id].workflow->pcap_handle);

        /* When using as extcap interface, the output/dumper pcap must have the same datalink
           type of the input traffic [to be able to use, for example, input pcaps with
           Linux "cooked" capture encapsulation (i.e. captured with "any" interface...) where
           there isn't an ethernet header] */
        if (do_extcap_capture) {
            extcap_capture(datalink_type);
            if (datalink_type == DLT_EN10MB)
                extcap_add_crc = 1;
        }

        if (!ndpi_is_datalink_supported(datalink_type)) {
            printf("Unsupported datalink %d. Skip pcap\n", datalink_type);
            return;
        }
        DLOG(TAG_NDPI, "Looping detection");
        int ret = pcap_loop(ndpi_thread_info[thread_id].workflow->pcap_handle, -1, &ndpi_process_packet, (u_char*)&thread_id);
        DLOG(TAG_NDPI, "Looping Done");
        if (ret == -1)
            printf("Error while reading pcap file: '%s'\n", pcap_geterr(ndpi_thread_info[thread_id].workflow->pcap_handle));
    }
}
#endif

/**
 * @brief Process a running thread
 */
void* processing_thread(void* _thread_id) {
#ifdef WIN64
    long long int thread_id = (long long int)_thread_id;
#else
    long int thread_id = (long int)_thread_id;
#endif
#ifndef USE_DPDK
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];
#endif

#if defined(__linux__) && defined(HAVE_PTHREAD_SETAFFINITY_NP)
    if (core_affinity[thread_id] >= 0) {
        cpu_set_t cpuset;

        CPU_ZERO(&cpuset);
        CPU_SET(core_affinity[thread_id], &cpuset);

        if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0)
            fprintf(stderr, "Error while binding thread %ld to core %d\n", thread_id, core_affinity[thread_id]);
        else {
            if (!quiet_mode) printf("Running thread %ld on core %d...\n", thread_id, core_affinity[thread_id]);
        }
    }
    else
#endif
        if ((!quiet_mode)) {
#ifdef WIN64
            printf("Running thread %lld...\n", thread_id);
#else
            printf("Running thread %ld...\n", thread_id);
#endif
        }

#ifdef USE_DPDK
    while (dpdk_run_capture) {
        struct rte_mbuf* bufs[BURST_SIZE];
        u_int16_t num = rte_eth_rx_burst(dpdk_port_id, 0, bufs, BURST_SIZE);
        u_int i;

        if (num == 0) {
            usleep(1);
            continue;
        }

        for (i = 0; i < PREFETCH_OFFSET && i < num; i++)
            rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void*));

        for (i = 0; i < num; i++) {
            char* data = rte_pktmbuf_mtod(bufs[i], char*);
            int len = rte_pktmbuf_pkt_len(bufs[i]);
            struct pcap_pkthdr h;

            h.len = h.caplen = len;
            gettimeofday(&h.ts, NULL);

            ndpi_process_packet((u_char*)&thread_id, &h, (const u_char*)data);
            rte_pktmbuf_free(bufs[i]);
        }
    }
#else
pcap_loop:
    runPcapLoop(thread_id);

    if (ndpi_thread_info[thread_id].workflow->pcap_handle)
        pcap_close(ndpi_thread_info[thread_id].workflow->pcap_handle);

    ndpi_thread_info[thread_id].workflow->pcap_handle = NULL;

    if (playlist_fp[thread_id] != NULL) { /* playlist: read next file */
        char filename[256];

        if (getNextPcapFileFromPlaylist(thread_id, filename, sizeof(filename)) == 0 &&
            (ndpi_thread_info[thread_id].workflow->pcap_handle = pcap_open_offline(filename, pcap_error_buffer)) != NULL) {
            configurePcapHandle(ndpi_thread_info[thread_id].workflow->pcap_handle);
            goto pcap_loop;
        }
    }
#endif
    if (bpf_cfilter) {
        pcap_freecode(bpf_cfilter);
        bpf_cfilter = NULL;
    }

    return NULL;
}

/* ***************************************************** */
#ifndef DEPLOY_BUILD
/**
 * @brief Begin, process, end test detection process
 */
void run_test() {
    u_int64_t processing_time_usec, setup_time_usec;
#ifdef WIN64
    long long int thread_id;
#else
    long thread_id;
#endif
    struct ndpi_global_context* g_ctx;

    set_ndpi_malloc(ndpi_malloc_wrapper), set_ndpi_free(free_wrapper);
    set_ndpi_flow_malloc(NULL), set_ndpi_flow_free(NULL);

#ifndef USE_GLOBAL_CONTEXT
  /* ndpiReader works even if libnDPI has been compiled without global context support,
     but you can't configure any cache with global scope */
    g_ctx = NULL;
#else
    g_ctx = ndpi_global_init();
    if (!g_ctx) {
        fprintf(stderr, "Error ndpi_global_init\n");
        exit(-1);
    }
#endif

#ifdef DEBUG_TRACE
    if (trace_fp) fprintf(trace_fp, "Num threads: %d\n", num_threads);
#endif

    for (thread_id = 0; thread_id < num_threads; thread_id++) {
        pcap_t* cap;

#ifdef DEBUG_TRACE
        if (trace_fp) fprintf(trace_fp, "Opening %s\n", (const u_char*)_pcap_file[thread_id]);
#endif

        cap = openPcapFileOrDevice(thread_id, (const u_char*)_pcap_file[thread_id]);
        setupDetection(thread_id, cap, g_ctx);
    }

    gettimeofday(&begin, NULL);

    int status;
    void* thd_res;

    /* Running processing threads */
    for (thread_id = 0; thread_id < num_threads; thread_id++) {
        status = pthread_create(&ndpi_thread_info[thread_id].pthread, NULL, processing_thread, (void*)thread_id);
        /* check pthreade_create return value */
        if (status != 0) {
#ifdef WIN64
            fprintf(stderr, "error on create %lld thread\n", thread_id);
#else
            fprintf(stderr, "error on create %ld thread\n", thread_id);
#endif
            exit(-1);
        }
    }
    /* Waiting for completion */
    for (thread_id = 0; thread_id < num_threads; thread_id++) {
        status = pthread_join(ndpi_thread_info[thread_id].pthread, &thd_res);
        /* check pthreade_join return value */
        if (status != 0) {
#ifdef WIN64
            fprintf(stderr, "error on join %lld thread\n", thread_id);
#else
            fprintf(stderr, "error on join %ld thread\n", thread_id);
#endif
            exit(-1);
        }
        if (thd_res != NULL) {
#ifdef WIN64
            fprintf(stderr, "error on returned value of %lld joined thread\n", thread_id);
#else
            fprintf(stderr, "error on returned value of %ld joined thread\n", thread_id);
#endif
            exit(-1);
        }
    }

#ifdef USE_DPDK
    dpdk_port_deinit(dpdk_port_id);
#endif

    gettimeofday(&end, NULL);
    processing_time_usec = (u_int64_t)end.tv_sec * 1000000 + end.tv_usec - ((u_int64_t)begin.tv_sec * 1000000 + begin.tv_usec);
    setup_time_usec = (u_int64_t)begin.tv_sec * 1000000 + begin.tv_usec - ((u_int64_t)startup_time.tv_sec * 1000000 + startup_time.tv_usec);

    /* Printing cumulative results */
    printResults(processing_time_usec, setup_time_usec);

    for (thread_id = 0; thread_id < num_threads; thread_id++) {
        if (ndpi_thread_info[thread_id].workflow->pcap_handle != NULL)
            pcap_close(ndpi_thread_info[thread_id].workflow->pcap_handle);

        terminateDetection(thread_id);
    }

    ndpi_global_deinit(g_ctx);
}
#else
/**
 * @brief Begin, process, end detection process
 */
void run_detection() {
    u_int64_t processing_time_usec, setup_time_usec;
#ifdef WIN64
    long long int thread_id;
#else
    long thread_id;
#endif
    struct ndpi_global_context* g_ctx;

    set_ndpi_malloc(ndpi_malloc_wrapper), set_ndpi_free(free_wrapper);
    set_ndpi_flow_malloc(NULL), set_ndpi_flow_free(NULL);

#ifndef USE_GLOBAL_CONTEXT
  /* ndpiReader works even if libnDPI has been compiled without global context support,
     but you can't configure any cache with global scope */
    g_ctx = NULL;
#else
    g_ctx = ndpi_global_init();
    if (!g_ctx) {
        fprintf(stderr, "Error ndpi_global_init\n");
        exit(-1);
    }
#endif

#ifdef DEBUG_TRACE
    if (trace_fp) fprintf(trace_fp, "Num threads: %d\n", num_threads);
#endif

    for (thread_id = 0; thread_id < num_threads; thread_id++) {
        pcap_t* cap;

#ifdef DEBUG_TRACE
        if (trace_fp) fprintf(trace_fp, "Opening %s\n", (const u_char*)_pcap_file[thread_id]);
#endif

        cap = openPcapFileOrDevice(thread_id, (const u_char*)_pcap_file[thread_id]);
        setupDetection(thread_id, cap, g_ctx);
    }

    gettimeofday(&begin, NULL);

    int status;
    void* thd_res;

    ILOG(TAG_GENERAL, "Program execution starting with %d threads...", num_threads);

    // pthread_t display_thread;
    // pthread_create(&display_thread, NULL, ldis_print, NULL);

    thread_pool_assign(&global_thread_pool, THREAD_DISPLAY, ldis_print, NULL, NULL);

    /* Running processing threads */
    for (thread_id = 0; thread_id < num_threads; thread_id++) {
        status = pthread_create(&ndpi_thread_info[thread_id].pthread, NULL, processing_thread, (void*)thread_id);
        /* check pthreade_create return value */
        if (status != 0) {
#ifdef WIN64
            fprintf(stderr, "error on create %lld thread\n", thread_id);
#else
            fprintf(stderr, "error on create %ld thread\n", thread_id);
#endif
            exit(-1);
        }
    }
    /* Waiting for completion */
    for (thread_id = 0; thread_id < num_threads; thread_id++) {
        status = pthread_join(ndpi_thread_info[thread_id].pthread, &thd_res);
        /* check pthreade_join return value */
        if (status != 0) {
#ifdef WIN64
            fprintf(stderr, "error on join %lld thread\n", thread_id);
#else
            fprintf(stderr, "error on join %ld thread\n", thread_id);
#endif
            exit(-1);
        }
        if (thd_res != NULL) {
#ifdef WIN64
            fprintf(stderr, "error on returned value of %lld joined thread\n", thread_id);
#else
            fprintf(stderr, "error on returned value of %ld joined thread\n", thread_id);
#endif
            exit(-1);
        }
    }
    ldis_do_loop = 0;

    DLOG(TAG_GENERAL, "Execution completed...");

#ifdef USE_DPDK
    dpdk_port_deinit(dpdk_port_id);
#endif

    // _TODO: Execution completion event instead of busy waiting
    while (global_thread_pool.handler[THREAD_DISPLAY].thread_queue_len > 0) {
        zmq_sleep(1);
    }

    gettimeofday(&end, NULL);
    processing_time_usec = (u_int64_t)end.tv_sec * 1000000 + end.tv_usec - ((u_int64_t)begin.tv_sec * 1000000 + begin.tv_usec);
    setup_time_usec = (u_int64_t)begin.tv_sec * 1000000 + begin.tv_usec - ((u_int64_t)startup_time.tv_sec * 1000000 + startup_time.tv_usec);

    /* Printing cumulative results */
    printResults(processing_time_usec, setup_time_usec);
    ILOG(TAG_GENERAL, "Printing completed...");

    for (thread_id = 0; thread_id < num_threads; thread_id++) {
        if (ndpi_thread_info[thread_id].workflow->pcap_handle != NULL)
            pcap_close(ndpi_thread_info[thread_id].workflow->pcap_handle);

        terminateDetection(thread_id);
    }

    ndpi_global_deinit(g_ctx);
}
#endif

/* *********************************************** */

/**
 * @brief Initialize port array
 */

void bpf_filter_port_array_init(int array[], int size) {
    int i;
    for (i = 0; i < size; i++)
        array[i] = INIT_VAL;
}

/* *********************************************** */
/**
 * @brief Initialize host array
 */

void bpf_filter_host_array_init(const char* array[48], int size) {
    int i;
    for (i = 0; i < size; i++)
        array[i] = NULL;
}

/* *********************************************** */

/**
 * @brief Add host to host filter array
 */

void bpf_filter_host_array_add(const char* filter_array[48], int size, const char* host) {
    int i;
    int r;
    for (i = 0; i < size; i++) {
        if ((filter_array[i] != NULL) && (r = strcmp(filter_array[i], host)) == 0)
            return;
        if (filter_array[i] == NULL) {
            filter_array[i] = host;
            return;
        }
    }
    fprintf(stderr, "bpf_filter_host_array_add: max array size is reached!\n");
    exit(-1);
}


/* *********************************************** */

/**
 * @brief Add port to port filter array
 */

void bpf_filter_port_array_add(int filter_array[], int size, int port) {
    int i;
    for (i = 0; i < size; i++) {
        if (filter_array[i] == port)
            return;
        if (filter_array[i] == INIT_VAL) {
            filter_array[i] = port;
            return;
        }
    }
    fprintf(stderr, "bpf_filter_port_array_add: max array size is reached!\n");
    exit(-1);
}

/* *********************************************** */

void run() {
    global_init();
    ILOG(TAG_GENERAL, "Program is starting...");

    if (!quiet_mode) {
        printf("Using nDPI (%s) [%d thread(s)]\n", ndpi_revision(), num_threads);

        const char* gcrypt_ver = ndpi_get_gcrypt_version();
        if (gcrypt_ver)
            printf("Using libgcrypt version %s\n", gcrypt_ver);
    }

    signal(SIGINT, sigproc);

    for (int i = 0; i < num_loops; i++) {
#ifndef DEPLOY_BUILD
        run_test();
#else
        run_detection();
#endif
    }

    if (results_path)  ndpi_free(results_path);
    if (results_file)  fclose(results_file);
    if (extcap_dumper) pcap_dump_close(extcap_dumper);
    if (extcap_fifo_h) pcap_close(extcap_fifo_h);
    if (enable_malloc_bins) ndpi_free_bin(&malloc_bins);
    if (csv_fp)         fclose(csv_fp);
    if (fingerprint_fp) fclose(fingerprint_fp);


    ndpi_free(_disabled_protocols);

    for (int i = 0; i < num_cfgs; i++) {
        ndpi_free(cfgs[i].proto);
        ndpi_free(cfgs[i].param);
        ndpi_free(cfgs[i].value);
    }

#ifdef DEBUG_TRACE
    if (trace_fp) fclose(trace_fp);
#endif

    ILOG(TAG_GENERAL, "Program is stopping...");
    global_clean();
}

/**
   @brief MAIN FUNCTION
**/
int main(int argc, char** argv) {
#ifdef DEBUG_TRACE
    trace_fp = fopen("./out.ignore/debug.log", "a");

    if (trace_fp) {
        int i;

        fprintf(trace_fp, " #### %s #### \n", __FUNCTION__);
        fprintf(trace_fp, " #### [argc: %u] #### \n", argc);

        for (i = 0; i < argc; i++)
            fprintf(trace_fp, " #### [%d] [%s]\n", i, argv[i]);
    }
#endif

    if (ndpi_get_api_version() != NDPI_API_VERSION) {
        printf("nDPI Library version mismatch: please make sure this code and the nDPI library are in sync\n");
        return(-1);
    }

#ifndef DEPLOY_BUILD
#ifdef NDPI_EXTENDED_SANITY_CHECKS
    int skip_unit_tests = 0;
#else
    int skip_unit_tests = 1;
#endif

    if (!skip_unit_tests) {
#ifndef DEBUG_TRACE
/* Skip tests when debugging */

#ifdef HW_TEST
        hwUnitTest();
        hwUnitTest2();
        hwUnitTest3();
#endif

#ifdef STRESS_TEST
        desUnitStressTest();
        exit(0);
#endif

        domainCacheTestUnit();
        cryptDecryptUnitTest();
        kdUnitTest();
        encodeDomainsUnitTest();
        loadStressTest();
        domainsUnitTest();
        outlierUnitTest();
        pearsonUnitTest();
        binaryBitmapUnitTest();
        domainSearchUnitTest();
        domainSearchUnitTest2();
        sketchUnitTest();
        linearUnitTest();
        zscoreUnitTest();
        sesUnitTest();
        desUnitTest();

        /* Internal checks */
        // binUnitTest();
        jitterUnitTest();
        rsiUnitTest();
        hashUnitTest();
        dgaUnitTest();
        hllUnitTest();
        bitmapUnitTest();
        automataUnitTest();
        automataDomainsUnitTest();
        filterUnitTest();
        analyzeUnitTest();
        ndpi_self_check_host_match(stderr);
        analysisUnitTest();
        compressedBitmapUnitTest();
        strtonumUnitTest();
        strlcpyUnitTest();
        strnstrUnitTest();
        strncasestrUnitTest();
        memmemUnitTest();
        mahalanobisUnitTest();
#endif
    }
#endif

    gettimeofday(&startup_time, NULL);
    memset(ndpi_thread_info, 0, sizeof(ndpi_thread_info));

    if (getenv("AHO_DEBUG"))
        ac_automata_enable_debug(1);
    parseOptions(argc, argv);

    if (domain_to_check) {
        ndpiCheckHostStringMatch(domain_to_check);
        exit(0);
    }
    if (ip_port_to_check) {
        ndpiCheckIPMatch(ip_port_to_check);
        exit(0);
    }

    if (enable_doh_dot_detection) {
        init_doh_bins();
        /* Clusters are not really used in DoH/DoT detection, but because of how
           the code has been written, we need to enable also clustering feature */
        if (num_bin_clusters == 0)
            num_bin_clusters = 1;
    }

    run();

    return 0;
}

#ifdef _MSC_BUILD
int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    if (AttachConsole(ATTACH_PARENT_PROCESS)) {
        freopen("CONIN$", "r", stdin);
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);
    }

    return main(__argc, __argv);
}
#endif

#if defined(WIN32) && !defined(_MSC_BUILD)
#ifndef __GNUC__
#define EPOCHFILETIME (116444736000000000i64)
#else
#define EPOCHFILETIME (116444736000000000LL)
#endif

  /**
     @brief Timezone
  **/
#ifndef __GNUC__
struct timezone {
    int tz_minuteswest; /* minutes W of Greenwich */
    int tz_dsttime;     /* type of dst correction */
};
#endif

  /**
     @brief Set time
  **/
int gettimeofday(struct timeval* tv, struct timezone* tz) {
    FILETIME        ft;
    LARGE_INTEGER   li;
    __int64         t;
    static int      tzflag;

    if (tv) {
        GetSystemTimeAsFileTime(&ft);
        li.LowPart = ft.dwLowDateTime;
        li.HighPart = ft.dwHighDateTime;
        t = li.QuadPart;       /* In 100-nanosecond intervals */
        t -= EPOCHFILETIME;     /* Offset to the Epoch time */
        t /= 10;                /* In microseconds */
        tv->tv_sec = (long)(t / 1000000);
        tv->tv_usec = (long)(t % 1000000);
    }

    if (tz) {
        if (!tzflag) {
            _tzset();
            tzflag++;
        }

        tz->tz_minuteswest = _timezone / 60;
        tz->tz_dsttime = _daylight;
    }

    return 0;
}
#endif /* WIN32 */
