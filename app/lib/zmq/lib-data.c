#include "../../include/lib-data.h"

/* ********************************** */

void data_memory_get(struct data_memory* data_memory) {
    data_memory->mem_once = ndpi_get_ndpi_detection_module_size();
    data_memory->mem_per_flow = ndpi_detection_get_sizeof_ndpi_flow_struct();
    data_memory->mem_actual = current_ndpi_memory;
    data_memory->mem_peak = max_ndpi_memory;
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

void data_time_get(
    struct data_time* data_time,
    uint64_t processing_time_usec,
    uint64_t setup_time_usec
) {
    data_time->setup_time = (unsigned long)(setup_time_usec / 1000);
    data_time->processing_time = (unsigned long)(processing_time_usec / 1000);
}

json_object* data_time_to_json(struct data_time* data) {
    json_object* retval = json_object_new_object();

    json_object_object_add(retval, "setup_time", json_object_new_uint64(data->setup_time));
    json_object_object_add(retval, "processing_time", json_object_new_uint64(data->processing_time));

    return retval;
}

/* ********************************** */

void data_traffic_get(
    struct data_traffic* data_traffic,
    ndpi_stats_t stats,
    uint64_t processing_time_usec
) {
    data_traffic->total_wire_bytes = stats.total_wire_bytes;
    data_traffic->total_discarded_bytes = stats.total_discarded_bytes;
    data_traffic->raw_packet_count = stats.raw_packet_count;
    data_traffic->ip_packet_count = stats.ip_packet_count;
    data_traffic->total_ip_bytes = stats.total_ip_bytes;
    data_traffic->ndpi_flow_count = stats.ndpi_flow_count;
    data_traffic->tcp_count = stats.tcp_count;
    data_traffic->udp_count = stats.udp_count;
    data_traffic->vlan_count = stats.vlan_count;
    data_traffic->mpls_count = stats.mpls_count;
    data_traffic->pppoe_count = stats.pppoe_count;
    data_traffic->fragmented_count = stats.fragmented_count;
    data_traffic->max_packet_len = stats.max_packet_len;
    data_traffic->packet_less_64 = stats.packet_len[0];
    data_traffic->packet_range_64_to_128 = stats.packet_len[1];
    data_traffic->packet_range_128_to_256 = stats.packet_len[2];
    data_traffic->packet_range_256_to_1024 = stats.packet_len[3];
    data_traffic->packet_range_1024_to_1500 = stats.packet_len[4];
    data_traffic->packet_larger_1500 = stats.packet_len[5];

    if (stats.total_ip_bytes && stats.raw_packet_count) {
        data_traffic->avg_pkt_size = (unsigned int)(stats.total_ip_bytes / stats.raw_packet_count);
    }
    else {
        data_traffic->avg_pkt_size = 0;
    }

    if (processing_time_usec > 0) {
        float t = (float)(stats.ip_packet_count * 1000000) / (float)processing_time_usec;
        float b = (float)(stats.total_wire_bytes * 8 * 1000000) / (float)processing_time_usec;

        data_traffic->ndpi_packets_per_second = t;
        data_traffic->ndpi_bytes_per_second = b;
        data_traffic->start_time = (long)pcap_start.tv_sec;
        data_traffic->end_time = (long)pcap_end.tv_sec;

        if (live_capture) data_traffic->traffic_duration = processing_time_usec;
        else data_traffic->traffic_duration = ((u_int64_t)pcap_end.tv_sec * 1000000 + pcap_end.tv_usec) - ((u_int64_t)pcap_start.tv_sec * 1000000 + pcap_start.tv_usec);

        if (data_traffic->traffic_duration != 0) {
            t = (float)(stats.ip_packet_count * 1000000) / data_traffic->traffic_duration;
            b = (float)(stats.total_wire_bytes * 8 * 1000000) / data_traffic->traffic_duration;
        }
        else {
            t = 0;
            b = 0;
        }

        data_traffic->traffic_packets_per_second = t;
        data_traffic->traffic_bytes_per_second = b;
    }
    data_traffic->guessed_flow_protocols = stats.guessed_flow_protocols;
    data_traffic->dpi_tcp_count = stats.dpi_packet_count[0];
    data_traffic->dpi_udp_count = stats.dpi_packet_count[1];
    data_traffic->dpi_other_count = stats.dpi_packet_count[2];
    data_traffic->dpi_tcp_flow = stats.flow_count[0];
    data_traffic->dpi_udp_flow = stats.flow_count[1];
    data_traffic->dpi_other_flow = stats.flow_count[2];

    // _TODO: Port confidence
}

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
    json_object_object_add(retval, "packet_less_64", json_object_new_uint64(data->packet_less_64));
    json_object_object_add(retval, "packet_range_64_to_128", json_object_new_uint64(data->packet_range_64_to_128));
    json_object_object_add(retval, "packet_range_128_to_256", json_object_new_uint64(data->packet_range_128_to_256));
    json_object_object_add(retval, "packet_range_256_to_1024", json_object_new_uint64(data->packet_range_256_to_1024));
    json_object_object_add(retval, "packet_range_1024_to_1500", json_object_new_uint64(data->packet_range_1024_to_1500));
    json_object_object_add(retval, "packet_larger_1500", json_object_new_uint64(data->packet_larger_1500));
    json_object_object_add(retval, "ndpi_packets_per_second", json_object_new_double((double)data->ndpi_packets_per_second));
    json_object_object_add(retval, "ndpi_bytes_per_second", json_object_new_double((double)data->ndpi_bytes_per_second));

    // _TODO: format as string instead
    json_object_object_add(retval, "start_time", json_object_new_int64(data->start_time));
    json_object_object_add(retval, "end_time", json_object_new_int64(data->end_time));
    json_object_object_add(retval, "traffic_duration", json_object_new_double((double)data->traffic_duration));

    json_object_object_add(retval, "traffic_packets_per_second", json_object_new_double((double)data->traffic_packets_per_second));
    json_object_object_add(retval, "traffic_bytes_per_second", json_object_new_double((double)data->traffic_bytes_per_second));
    json_object_object_add(retval, "guessed_flow_protocols", json_object_new_uint64(data->guessed_flow_protocols));
    json_object_object_add(retval, "dpi_tcp_count", json_object_new_uint64(data->dpi_tcp_count));
    json_object_object_add(retval, "dpi_udp_count", json_object_new_uint64(data->dpi_udp_count));
    json_object_object_add(retval, "dpi_other_count", json_object_new_uint64(data->dpi_other_count));
    json_object_object_add(retval, "dpi_tcp_flow", json_object_new_uint64(data->dpi_tcp_flow));
    json_object_object_add(retval, "dpi_udp_flow", json_object_new_uint64(data->dpi_udp_flow));
    json_object_object_add(retval, "dpi_other_flow", json_object_new_uint64(data->dpi_other_flow));

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
