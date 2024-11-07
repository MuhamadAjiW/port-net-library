#include "../../include/lib-data.h"

/* ********************************** */

json_object* data_memory_to_json(struct data_memory* data) {
    json_object* retval = json_object_new_object();

    json_object_object_add(retval, "mem_once", json_object_new_uint64((uint64_t)data->mem_once));
    json_object_object_add(retval, "mem_per_flow", json_object_new_uint64((uint64_t)data->mem_per_flow));
    json_object_object_add(retval, "mem_actual", json_object_new_uint64((uint64_t)data->mem_actual));
    json_object_object_add(retval, "mem_peak", json_object_new_uint64((uint64_t)data->mem_peak));

    return retval;
}

/* ********************************** */

json_object* data_time_to_json(struct data_time* data) {
    json_object* retval = json_object_new_object();

    json_object_object_add(retval, "setup_time", json_object_new_uint64(data->setup_time));
    json_object_object_add(retval, "processing_time", json_object_new_uint64(data->processing_time));

    return retval;
}

/* ********************************** */

json_object* data_traffic_to_json(struct data_traffic* data) {
    json_object* retval = json_object_new_object();

    json_object_object_add(retval, "total_wire_bytes", json_object_new_uint64(data->total_wire_bytes));
    json_object_object_add(retval, "total_discarded_bytes", json_object_new_uint64(data->total_discarded_bytes));
    json_object_object_add(retval, "raw_packet_count", json_object_new_uint64(data->raw_packet_count));
    json_object_object_add(retval, "ip_packet_count", json_object_new_uint64(data->ip_packet_count));
    json_object_object_add(retval, "avg_pkt_size", json_object_new_uint64(data->avg_pkt_size));
    json_object_object_add(retval, "total_ip_bytes", json_object_new_uint64(data->total_ip_bytes));
    json_object_object_add(retval, "ndpi_flow_count", json_object_new_uint64(data->ndpi_flow_count));
    json_object_object_add(retval, "tcp_count", json_object_new_uint64(data->tcp_count));
    json_object_object_add(retval, "udp_count", json_object_new_uint64(data->udp_count));
    json_object_object_add(retval, "vlan_count", json_object_new_uint64(data->vlan_count));
    json_object_object_add(retval, "mpls_count", json_object_new_uint64(data->mpls_count));
    json_object_object_add(retval, "pppoe_count", json_object_new_uint64(data->pppoe_count));
    json_object_object_add(retval, "fragmented_count", json_object_new_uint64(data->fragmented_count));
    json_object_object_add(retval, "max_packet_len", json_object_new_uint64(data->max_packet_len));
    json_object_object_add(retval, "packet_less_64", json_object_new_uint64(data->packet_len[PACKET_LESS_64]));
    json_object_object_add(retval, "packet_range_64_to_128", json_object_new_uint64(data->packet_len[PACKET_RANGE_64_128]));
    json_object_object_add(retval, "packet_range_128_to_256", json_object_new_uint64(data->packet_len[PACKET_RANGE_128_256]));
    json_object_object_add(retval, "packet_range_256_to_1024", json_object_new_uint64(data->packet_len[PACKET_RANGE_256_1024]));
    json_object_object_add(retval, "packet_range_1024_to_1500", json_object_new_uint64(data->packet_len[PACKET_RANGE_1024_1500]));
    json_object_object_add(retval, "packet_larger_1500", json_object_new_uint64(data->packet_len[PACKET_MORE_1500]));
    json_object_object_add(retval, "ndpi_packets_per_second", json_object_new_double((double)data->ndpi_packets_per_second));
    json_object_object_add(retval, "ndpi_bytes_per_second", json_object_new_double((double)data->ndpi_bytes_per_second));

    // _TODO: format as string instead
    json_object_object_add(retval, "start_time", json_object_new_int64(data->start_time));
    json_object_object_add(retval, "end_time", json_object_new_int64(data->end_time));
    json_object_object_add(retval, "traffic_duration", json_object_new_double((double)data->traffic_duration));

    json_object_object_add(retval, "traffic_packets_per_second", json_object_new_double((double)data->traffic_packets_per_second));
    json_object_object_add(retval, "traffic_bytes_per_second", json_object_new_double((double)data->traffic_bytes_per_second));
    json_object_object_add(retval, "guessed_flow_protocols", json_object_new_uint64(data->guessed_flow_protocols));
    json_object_object_add(retval, "dpi_tcp_count", json_object_new_uint64(data->dpi_packet_count[FLOW_TCP]));
    json_object_object_add(retval, "dpi_udp_count", json_object_new_uint64(data->dpi_packet_count[FLOW_UDP]));
    json_object_object_add(retval, "dpi_other_count", json_object_new_uint64(data->dpi_packet_count[FLOW_OTHER]));
    json_object_object_add(retval, "dpi_tcp_flow", json_object_new_uint64(data->dpi_flow_count[FLOW_TCP]));
    json_object_object_add(retval, "dpi_udp_flow", json_object_new_uint64(data->dpi_flow_count[FLOW_UDP]));
    json_object_object_add(retval, "dpi_other_flow", json_object_new_uint64(data->dpi_flow_count[FLOW_OTHER]));

    // _TODO: Port confidence

    return retval;
}

/* ********************************** */

void data_protocol_get(
    struct data_protocol* data_protocol,
    char* name,
    uint64_t packet_count,
    uint64_t byte_count,
    uint64_t flow_count
) {
    data_protocol->name = str_new(name);
    data_protocol->packet_count = packet_count;
    data_protocol->byte_count = byte_count;
    data_protocol->flow_count = flow_count;
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

void data_classification_get(
    struct data_classification* data_classification,
    char* name,
    uint64_t packet_count,
    uint64_t byte_count,
    uint64_t flow_count
) {
    data_classification->name = str_new(name);
    data_classification->packet_count = packet_count;
    data_classification->byte_count = byte_count;
    data_classification->flow_count = flow_count;
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

/* ********************************** */

void data_risk_get(
    struct data_risk* data_risk,
    char* name,
    uint64_t flow_count,
    float ratio
) {
    data_risk->name = str_new(name);
    data_risk->flow_count = flow_count;
    data_risk->ratio = ratio;
}

void data_risk_clean(struct data_risk* data) {
    str_delete(&data->name);
}

json_object* data_risk_to_json(struct data_risk* data) {
    json_object* retval = json_object_new_object();

    json_object_object_add(retval, "name", json_object_new_string(data->name.content));
    json_object_object_add(retval, "flow_count", json_object_new_int(data->flow_count));
    json_object_object_add(retval, "ratio", json_object_new_double((double)data->ratio));

    return retval;
}

/* ********************************** */

json_object* data_flow_to_json(struct flow_info* data) {
    // _TODO: Implement
    return NULL;
}
