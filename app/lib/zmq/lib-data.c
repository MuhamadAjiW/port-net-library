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
    json_object* retval = json_object_new_object();

    // _TODO: Will better to fetch it during generation to avoid repetition
    struct ndpi_detection_module_struct* ndpi_dm_struct = ndpi_thread_info[0].workflow->ndpi_struct;

    struct ndpi_flow_info* flow = data->flow;
    char buf[256];

    json_object_object_add(retval, "transport_protocol", json_object_new_string(ndpi_get_ip_proto_name(flow->protocol, buf, sizeof(buf))));
    json_object_object_add(retval, "ip_version", json_object_new_uint64((unsigned long long) flow->ip_version));
    json_object_object_add(retval, "src_ip", json_object_new_string(flow->src_name));
    json_object_object_add(retval, "src_port", json_object_new_uint64((unsigned long long) flow->src_name));
    json_object_object_add(retval, "dst_ip", json_object_new_string(flow->dst_name));
    json_object_object_add(retval, "dst_port", json_object_new_uint64((unsigned long long) flow->dst_name));
    json_object_object_add(retval, "bidirectional", json_object_new_boolean(flow->bidirectional));
    json_object_object_add(retval, "vlan_id", json_object_new_uint64((unsigned long long) flow->vlan_id));
    json_object_object_add(retval, "tunnel", json_object_new_string(ndpi_tunnel2str(flow->tunnel_type)));
    json_object_object_add(retval, "application_protocol", json_object_new_string(ndpi_protocol2name(ndpi_dm_struct, flow->detected_protocol, buf, sizeof(buf))));
    json_object_object_add(retval, "ip_owner", json_object_new_string(ndpi_get_proto_name(ndpi_dm_struct, flow->detected_protocol.protocol_by_ip)));
    json_object_object_add(retval, "encryption", json_object_new_boolean(ndpi_is_encrypted_proto(ndpi_dm_struct, flow->detected_protocol)));

    const char* content;
    switch (flow->multimedia_flow_type) {
    case ndpi_multimedia_audio_flow:
        content = "Audio";
        break;

    case ndpi_multimedia_video_flow:
        content = "Video";
        break;

    case ndpi_multimedia_screen_sharing_flow:
        content = "Screen Sharing";
        break;

    default:
        content = "???";
        break;
    }
    json_object_object_add(retval, "content_type", json_object_new_string(content));

    const char* fpc_info;
    if (flow->fpc.proto.master_protocol == NDPI_PROTOCOL_UNKNOWN) {
        fpc_info = ndpi_get_proto_name(ndpi_dm_struct, flow->fpc.proto.app_protocol);
    }
    else {
        snprintf(buf, sizeof(buf), "%s.%s",
            ndpi_get_proto_name(ndpi_dm_struct, flow->fpc.proto.master_protocol),
            ndpi_get_proto_name(ndpi_dm_struct, flow->fpc.proto.app_protocol));

        fpc_info = buf;
    }
    json_object_object_add(retval, "full_packet_capture", json_object_new_string(fpc_info));

    json_object_object_add(retval, "dpi_packets", json_object_new_uint64((unsigned long long)flow->dpi_packets));
    json_object_object_add(retval, "category", json_object_new_string(ndpi_category_get_name(ndpi_dm_struct, flow->detected_protocol.category)));
    json_object_object_add(retval, "outgoing_packet_count", json_object_new_uint64((unsigned long long)flow->src2dst_packets));
    json_object_object_add(retval, "outgoing_packet_size", json_object_new_uint64((unsigned long long)flow->src2dst_bytes));
    json_object_object_add(retval, "incoming_packet_count", json_object_new_uint64((unsigned long long)flow->dst2src_packets));
    json_object_object_add(retval, "incoming_packet_size", json_object_new_uint64((unsigned long long)flow->dst2src_bytes));
    json_object_object_add(retval, "outgoing_goodput_ratio", json_object_new_double((double)100.0 * ((float)flow->src2dst_goodput_bytes / (float)(flow->src2dst_bytes + 1))));
    json_object_object_add(retval, "incoming_goodput_ratio", json_object_new_double((double)100.0 * ((float)flow->dst2src_goodput_bytes / (float)(flow->dst2src_bytes + 1))));
    json_object_object_add(retval, "duration", json_object_new_double((double)((float)(flow->last_seen_ms - flow->first_seen_ms)) / (float)1000));
    json_object_object_add(retval, "hostname", json_object_new_string(flow->host_server_name));

    json_object* json_details = json_object_new_object();
    switch (flow->info_type)
    {
    case INFO_INVALID:
        json_object_object_add(retval, "info_type", json_object_new_string("invalid"));
        break;
    case INFO_GENERIC:
        json_object_object_add(retval, "info_type", json_object_new_string("generic"));
        json_object_object_add(json_details, "info", json_object_new_string(flow->info));
        break;
    case INFO_KERBEROS:
        json_object_object_add(retval, "info_type", json_object_new_string("kerberos"));
        json_object_object_add(json_details, "domain", json_object_new_string(flow->kerberos.domain));
        json_object_object_add(json_details, "hostname", json_object_new_string(flow->kerberos.hostname));
        json_object_object_add(json_details, "username", json_object_new_string(flow->kerberos.username));
        break;
    case INFO_SOFTETHER:
        json_object_object_add(retval, "info_type", json_object_new_string("softether"));
        json_object_object_add(json_details, "client_ip", json_object_new_string(flow->softether.ip));
        json_object_object_add(json_details, "client_port", json_object_new_string(flow->softether.port));
        json_object_object_add(json_details, "hostname", json_object_new_string(flow->softether.hostname));
        json_object_object_add(json_details, "fqdn", json_object_new_string(flow->softether.fqdn));
        break;
    case INFO_TIVOCONNECT:
        json_object_object_add(retval, "info_type", json_object_new_string("tivoconnect"));
        json_object_object_add(json_details, "uuid", json_object_new_string(flow->tivoconnect.identity_uuid));
        json_object_object_add(json_details, "machine", json_object_new_string(flow->tivoconnect.machine));
        json_object_object_add(json_details, "platform", json_object_new_string(flow->tivoconnect.platform));
        json_object_object_add(json_details, "services", json_object_new_string(flow->tivoconnect.services));
        break;
    case INFO_NATPMP:
        json_object_object_add(retval, "info_type", json_object_new_string("natpmp"));
        json_object_object_add(json_details, "result", json_object_new_uint64((unsigned long long)flow->natpmp.result_code));
        json_object_object_add(json_details, "internal_port", json_object_new_uint64((unsigned long long)flow->natpmp.internal_port));
        json_object_object_add(json_details, "external_port", json_object_new_uint64((unsigned long long)flow->natpmp.external_port));
        json_object_object_add(json_details, "external_address", json_object_new_string(flow->natpmp.ip));
        break;
    case INFO_FTP_IMAP_POP_SMTP:
        json_object_object_add(retval, "info_type", json_object_new_string("ftp_imap_pop_smtp"));
        json_object_object_add(json_details, "username", json_object_new_string(flow->ftp_imap_pop_smtp.username));
        json_object_object_add(json_details, "password", json_object_new_string(flow->ftp_imap_pop_smtp.password));
        json_object_object_add(json_details, "auth_failed", json_object_new_boolean(flow->ftp_imap_pop_smtp.auth_failed));
        break;
    default:
        break;
    }
    json_object_object_add(retval, "details", json_details);

    json_object_object_add(retval, "advertised_alpns",
        json_object_new_string(flow->ssh_tls.advertised_alpns ? flow->ssh_tls.advertised_alpns : ""));
    json_object_object_add(retval, "negotiated_alpn",
        json_object_new_string(flow->ssh_tls.negotiated_alpn ? flow->ssh_tls.negotiated_alpn : ""));
    json_object_object_add(retval, "tls_supported_versions",
        json_object_new_string(flow->ssh_tls.tls_supported_versions ? flow->ssh_tls.tls_supported_versions : ""));
    json_object_object_add(retval, "currency", json_object_new_string(flow->mining.currency));
    json_object_object_add(retval, "geolocation", json_object_new_string(flow->dns.geolocation_iata_code));

    // _TODO: Implement the rest
    return NULL;
}
