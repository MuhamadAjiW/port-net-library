#include "../../include/lib-data.h"

/* ********************************** */

struct data_memory data_memory_get() {
    struct data_memory retval = { 0 };

    retval.mem_once = ndpi_get_ndpi_detection_module_size();
    retval.mem_per_flow = ndpi_detection_get_sizeof_ndpi_flow_struct();
    retval.mem_actual = current_ndpi_memory;
    retval.mem_peak = max_ndpi_memory;

    return retval;
}

json_object* data_memory_to_json(struct data_memory* data) {
    json_object* retval = json_object_new_object();

    json_object_object_add(retval, "mem_once", json_object_new_uint64((uint64_t)data->mem_once));
    json_object_object_add(retval, "mem_per_flow", json_object_new_uint64((uint64_t)data->mem_per_flow));
    json_object_object_add(retval, "mem_actual", json_object_new_uint64((uint64_t)data->mem_actual));
    json_object_object_add(retval, "mem_peak", json_object_new_uint64((uint64_t)data->mem_peak));

    return retval;
}

/* ********************************** */

struct data_time data_time_get(uint64_t processing_time_usec, uint64_t setup_time_usec) {
    struct data_time retval = { 0 };

    retval.setup_time = (unsigned long)(setup_time_usec / 1000);
    retval.processing_time = (unsigned long)(processing_time_usec / 1000);

    return retval;
}

json_object* data_time_to_json(struct data_time* data) {
    json_object* retval = json_object_new_object();

    json_object_object_add(retval, "setup_time", json_object_new_uint64(data->setup_time));
    json_object_object_add(retval, "processing_time", json_object_new_uint64(data->processing_time));

    return retval;
}

/* ********************************** */

struct data_traffic data_traffic_get(ndpi_stats_t stats) {
    struct data_traffic retval = { 0 };

    retval.ethernet_bytes = stats.total_wire_bytes;
    retval.discarded_bytes = stats.total_discarded_bytes;
    retval.total_packets = stats.raw_packet_count;
    retval.ip_packets = stats.ip_packet_count;
    retval.ip_bytes = stats.total_ip_bytes;
    retval.unique_flows = stats.ndpi_flow_count;
    retval.tcp_packets = stats.tcp_count;
    retval.udp_packets = stats.udp_count;
    retval.vlan_packets = stats.vlan_count;
    retval.mpls_packets = stats.mpls_count;
    retval.ppoe_packets = stats.pppoe_count;
    retval.fragmented_packets = stats.fragmented_count;
    retval.max_packet_size = stats.max_packet_len;
    retval.packet_less_64 = stats.packet_len[0];
    retval.packet_range_64_to_128 = stats.packet_len[1];
    retval.packet_range_128_to_256 = stats.packet_len[2];
    retval.packet_range_256_to_1024 = stats.packet_len[3];
    retval.packet_range_1024_to_1500 = stats.packet_len[4];
    retval.packet_larger_1500 = stats.packet_len[5];

    return retval;
}

json_object* data_traffic_to_json(struct data_traffic* data) {
    json_object* retval = json_object_new_object();

    json_object_object_add(retval, "ethernet_bytes", json_object_new_uint64(data->ethernet_bytes));
    json_object_object_add(retval, "discarded_bytes", json_object_new_uint64(data->discarded_bytes));
    json_object_object_add(retval, "total_packets", json_object_new_uint64(data->total_packets));
    json_object_object_add(retval, "ip_packets", json_object_new_uint64(data->ip_packets));
    json_object_object_add(retval, "ip_bytes", json_object_new_uint64(data->ip_bytes));
    json_object_object_add(retval, "unique_flows", json_object_new_uint64(data->unique_flows));
    json_object_object_add(retval, "tcp_packets", json_object_new_uint64(data->tcp_packets));
    json_object_object_add(retval, "udp_packets", json_object_new_uint64(data->udp_packets));
    json_object_object_add(retval, "vlan_packets", json_object_new_uint64(data->vlan_packets));
    json_object_object_add(retval, "mpls_packets", json_object_new_uint64(data->mpls_packets));
    json_object_object_add(retval, "ppoe_packets", json_object_new_uint64(data->ppoe_packets));
    json_object_object_add(retval, "fragmented_packets", json_object_new_uint64(data->fragmented_packets));
    json_object_object_add(retval, "max_packet_size", json_object_new_uint64(data->max_packet_size));
    json_object_object_add(retval, "packet_less_64", json_object_new_uint64(data->packet_less_64));
    json_object_object_add(retval, "packet_range_64_to_128", json_object_new_uint64(data->packet_range_64_to_128));
    json_object_object_add(retval, "packet_range_128_to_256", json_object_new_uint64(data->packet_range_128_to_256));
    json_object_object_add(retval, "packet_range_256_to_1024", json_object_new_uint64(data->packet_range_256_to_1024));
    json_object_object_add(retval, "packet_range_1024_to_1500", json_object_new_uint64(data->packet_range_1024_to_1500));
    json_object_object_add(retval, "packet_larger_1500", json_object_new_uint64(data->packet_larger_1500));

    return retval;
}

/* ********************************** */

struct data_dpi data_dpi_get(ndpi_stats_t stats, uint64_t processing_time_usec) {
    struct data_dpi retval;
    float t = (float)(stats.ip_packet_count * 1000000) / (float)processing_time_usec;
    float b = (float)(stats.total_wire_bytes * 8 * 1000000) / (float)processing_time_usec;
    float traffic_duration;

    retval.ndpi_packets_per_second = t;
    retval.ndpi_bytes_per_second = b;
    retval.start_time = (long)pcap_start.tv_sec;
    retval.end_time = (long)pcap_end.tv_sec;

    if (live_capture) traffic_duration = processing_time_usec;
    else traffic_duration = ((u_int64_t)pcap_end.tv_sec * 1000000 + pcap_end.tv_usec) - ((u_int64_t)pcap_start.tv_sec * 1000000 + pcap_start.tv_usec);

    if (traffic_duration != 0) {
        t = (float)(stats.ip_packet_count * 1000000) / (float)traffic_duration;
        b = (float)(stats.total_wire_bytes * 8 * 1000000) / (float)traffic_duration;
    }
    else {
        t = 0;
        b = 0;
    }

    retval.traffic_packets_per_second = t;
    retval.traffic_bytes_per_second = b;
    retval.guessed_flow_protocols = stats.guessed_flow_protocols;
    retval.dpi_tcp = stats.dpi_packet_count[0];
    retval.dpi_udp = stats.dpi_packet_count[1];
    retval.dpi_other = stats.dpi_packet_count[2];

    // _TODO: Port confidence

    return retval;
}

json_object* data_dpi_to_json(struct data_dpi* data) {
    json_object* retval = json_object_new_object();

    json_object_object_add(retval, "ndpi_packets_per_second", json_object_new_double((double)data->ndpi_packets_per_second));
    json_object_object_add(retval, "ndpi_bytes_per_second", json_object_new_double((double)data->ndpi_bytes_per_second));
    json_object_object_add(retval, "start_time", json_object_new_int64(data->start_time));
    json_object_object_add(retval, "end_time", json_object_new_int64(data->end_time));
    json_object_object_add(retval, "traffic_packets_per_second", json_object_new_double((double)data->traffic_packets_per_second));
    json_object_object_add(retval, "traffic_bytes_per_second", json_object_new_double((double)data->traffic_bytes_per_second));
    json_object_object_add(retval, "guessed_flow_protocols", json_object_new_uint64(data->guessed_flow_protocols));
    json_object_object_add(retval, "dpi_tcp", json_object_new_uint64(data->dpi_tcp));
    json_object_object_add(retval, "dpi_udp", json_object_new_uint64(data->dpi_udp));
    json_object_object_add(retval, "dpi_other", json_object_new_uint64(data->dpi_other));

    return retval;
}

/* ********************************** */

struct data_protocol data_protocol_get(
    char* name,
    uint64_t packet_count,
    uint64_t byte_count,
    uint64_t flow_count
) {
    struct data_protocol retval;

    retval.name = str_new(name);
    retval.packet_count = packet_count;
    retval.byte_count = byte_count;
    retval.flow_count = flow_count;

    return retval;
}

void data_protocol_clean(struct data_protocol* data) {
    str_delete(&data->name);
}

json_object* data_protocol_to_json(struct data_protocol* data) {
    json_object* retval = json_object_new_object();

    json_object_object_add(retval, "name", json_object_new_string(data->name.content));
    json_object_object_add(retval, "packet_count", json_object_new_int64(data->packet_count));
    json_object_object_add(retval, "byte_count", json_object_new_int64(data->byte_count));
    json_object_object_add(retval, "flow_count", json_object_new_int64(data->flow_count));

    return retval;
}

/* ********************************** */

struct data_classification data_classification_get(
    char* name,
    uint64_t packet_count,
    uint64_t byte_count,
    uint64_t flow_count
) {
    struct data_classification retval;

    retval.name = str_new(name);
    retval.packet_count = packet_count;
    retval.byte_count = byte_count;
    retval.flow_count = flow_count;

    return retval;
}

void data_classification_clean(struct data_classification* data) {
    str_delete(&data->name);
}

json_object* data_classification_to_json(struct data_classification* data) {
    json_object* retval = json_object_new_object();

    json_object_object_add(retval, "name", json_object_new_string(data->name.content));
    json_object_object_add(retval, "packet_count", json_object_new_int64(data->packet_count));
    json_object_object_add(retval, "byte_count", json_object_new_int64(data->byte_count));
    json_object_object_add(retval, "flow_count", json_object_new_int64(data->flow_count));

    return retval;
}
