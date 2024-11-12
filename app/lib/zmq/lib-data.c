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

    json_object_object_add(retval, "setup_time_ms", json_object_new_uint64(data->setup_time));
    json_object_object_add(retval, "processing_time_ms", json_object_new_uint64(data->processing_time));

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
    struct tm time_format;
    char time_string[64];
#ifdef WIN32
      /* localtime() on Windows is thread-safe */
    time_t tv_sec = global_data.traffic.start_time;
    struct tm* tm_ptr = localtime(&tv_sec);
    time_format = *tm_ptr;
#else
    localtime_r(&global_data.traffic.start_time, &time_format);
#endif
    strftime(time_string, sizeof(time_string), "%d %b %Y %H:%M:%S", &time_format);
    json_object_object_add(retval, "start_time", json_object_new_string(time_string));

#ifdef WIN32
      /* localtime() on Windows is thread-safe */
    tv_sec = global_data.traffic.end_time;
    tm* tm_ptr = localtime(&tv_sec);
    time_format = *tm_ptr;
#else
    localtime_r(&global_data.traffic.end_time, &time_format);
#endif
    strftime(time_string, sizeof(time_string), "%d %b %Y %H:%M:%S", &time_format);
    json_object_object_add(retval, "end_time", json_object_new_string(time_string));

    json_object_object_add(retval, "traffic_duration_sec", json_object_new_double((double)data->traffic_duration));

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
    u_int8_t known_tls;
    char buf[256];
    char buf_ver[16];
    char unknown_cipher[8];

    // Base Info
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

    json_object_object_add(retval, "dpi_packets",
        json_object_new_uint64((unsigned long long)flow->dpi_packets));
    json_object_object_add(retval, "category",
        json_object_new_string(ndpi_category_get_name(ndpi_dm_struct, flow->detected_protocol.category)));
    json_object_object_add(retval, "outgoing_packet_count",
        json_object_new_uint64((unsigned long long)flow->src2dst_packets));
    json_object_object_add(retval, "outgoing_packet_size",
        json_object_new_uint64((unsigned long long)flow->src2dst_bytes));
    json_object_object_add(retval, "incoming_packet_count",
        json_object_new_uint64((unsigned long long)flow->dst2src_packets));
    json_object_object_add(retval, "incoming_packet_size",
        json_object_new_uint64((unsigned long long)flow->dst2src_bytes));
    json_object_object_add(retval, "outgoing_goodput_ratio",
        json_object_new_double((double)100.0 * ((float)flow->src2dst_goodput_bytes / (float)(flow->src2dst_bytes + 1))));
    json_object_object_add(retval, "incoming_goodput_ratio",
        json_object_new_double((double)100.0 * ((float)flow->dst2src_goodput_bytes / (float)(flow->dst2src_bytes + 1))));
    json_object_object_add(retval, "duration",
        json_object_new_double((double)((float)(flow->last_seen_ms - flow->first_seen_ms)) / (float)1000));
    json_object_object_add(retval, "hostname",
        json_object_new_string(flow->host_server_name));
    json_object_object_add(retval, "currency",
        json_object_new_string(flow->mining.currency));
    json_object_object_add(retval, "geolocation",
        json_object_new_string(flow->dns.geolocation_iata_code));
    json_object_object_add(retval, "bt_hash",
        json_object_new_string(
            flow->bittorent_hash != NULL ? flow->bittorent_hash : ""));
    json_object_object_add(retval, "dhcp_fingerprint",
        json_object_new_string(
            flow->dhcp_fingerprint != NULL ? flow->dhcp_fingerprint : ""));
    json_object_object_add(retval, "dhcp_class_id",
        json_object_new_string(
            flow->dhcp_class_ident ? flow->dhcp_class_ident : ""));
    json_object_object_add(retval, "plain_text",
        json_object_new_string(
            flow->has_human_readeable_strings ? flow->human_readeable_string_buffer : ""));

    // Details
    json_object* json_info_details = json_object_new_object();
    switch (flow->info_type)
    {
    case INFO_INVALID:
        json_object_object_add(retval, "info_type", json_object_new_string("invalid"));
        break;
    case INFO_GENERIC:
        json_object_object_add(retval, "info_type", json_object_new_string("generic"));
        json_object_object_add(json_info_details, "info", json_object_new_string(flow->info));
        break;
    case INFO_KERBEROS:
        json_object_object_add(retval, "info_type", json_object_new_string("kerberos"));
        json_object_object_add(json_info_details, "domain", json_object_new_string(flow->kerberos.domain));
        json_object_object_add(json_info_details, "hostname", json_object_new_string(flow->kerberos.hostname));
        json_object_object_add(json_info_details, "username", json_object_new_string(flow->kerberos.username));
        break;
    case INFO_SOFTETHER:
        json_object_object_add(retval, "info_type", json_object_new_string("softether"));
        json_object_object_add(json_info_details, "client_ip", json_object_new_string(flow->softether.ip));
        json_object_object_add(json_info_details, "client_port", json_object_new_string(flow->softether.port));
        json_object_object_add(json_info_details, "hostname", json_object_new_string(flow->softether.hostname));
        json_object_object_add(json_info_details, "fqdn", json_object_new_string(flow->softether.fqdn));
        break;
    case INFO_TIVOCONNECT:
        json_object_object_add(retval, "info_type", json_object_new_string("tivoconnect"));
        json_object_object_add(json_info_details, "uuid", json_object_new_string(flow->tivoconnect.identity_uuid));
        json_object_object_add(json_info_details, "machine", json_object_new_string(flow->tivoconnect.machine));
        json_object_object_add(json_info_details, "platform", json_object_new_string(flow->tivoconnect.platform));
        json_object_object_add(json_info_details, "services", json_object_new_string(flow->tivoconnect.services));
        break;
    case INFO_NATPMP:
        json_object_object_add(retval, "info_type", json_object_new_string("natpmp"));
        json_object_object_add(json_info_details, "result", json_object_new_uint64((unsigned long long)flow->natpmp.result_code));
        json_object_object_add(json_info_details, "internal_port", json_object_new_uint64((unsigned long long)flow->natpmp.internal_port));
        json_object_object_add(json_info_details, "external_port", json_object_new_uint64((unsigned long long)flow->natpmp.external_port));
        json_object_object_add(json_info_details, "external_address", json_object_new_string(flow->natpmp.ip));
        break;
    case INFO_FTP_IMAP_POP_SMTP:
        json_object_object_add(retval, "info_type", json_object_new_string("ftp_imap_pop_smtp"));
        json_object_object_add(json_info_details, "username", json_object_new_string(flow->ftp_imap_pop_smtp.username));
        json_object_object_add(json_info_details, "password", json_object_new_string(flow->ftp_imap_pop_smtp.password));
        json_object_object_add(json_info_details, "auth_failed", json_object_new_boolean(flow->ftp_imap_pop_smtp.auth_failed));
        break;
    default:
        break;
    }
    json_object_object_add(retval, "info_details", json_info_details);

    // TLS
    json_object* json_info_tls = json_object_new_object();
    json_object_object_add(json_info_tls, "advertised_alpns",
        json_object_new_string(flow->ssh_tls.advertised_alpns ? flow->ssh_tls.advertised_alpns : ""));
    json_object_object_add(json_info_tls, "negotiated_alpn",
        json_object_new_string(flow->ssh_tls.negotiated_alpn ? flow->ssh_tls.negotiated_alpn : ""));
    json_object_object_add(json_info_tls, "tls_supported_versions",
        json_object_new_string(flow->ssh_tls.tls_supported_versions ? flow->ssh_tls.tls_supported_versions : ""));
    json_object_object_add(json_info_tls, "ssl_version",
        json_object_new_string(
            flow->ssh_tls.ssl_version != 0 ? ndpi_ssl_version2str(buf_ver, sizeof(buf_ver),
                flow->ssh_tls.ssl_version, &known_tls) : ""));
    json_object_object_add(json_info_tls, "quic_version",
        json_object_new_string(
            flow->ssh_tls.quic_version != 0 ? ndpi_quic_version2str(buf_ver, sizeof(buf_ver),
                flow->ssh_tls.quic_version) : ""));
    json_object_object_add(json_info_tls, "hassh-c",
        json_object_new_string(flow->ssh_tls.client_hassh[0] != '\0' ? flow->ssh_tls.client_hassh : ""));

    json_object_object_add(json_info_tls, "ja3_client",
        json_object_new_string(flow->ssh_tls.ja3_client[0] != '\0' ? flow->ssh_tls.ja3_client : ""));
    json_object_object_add(json_info_tls, "ja3_client_category",
        json_object_new_string(flow->ssh_tls.ja3_client[0] != '\0' ? is_unsafe_cipher(flow->ssh_tls.client_unsafe_cipher) : ""));

    json_object_object_add(json_info_tls, "ja4_client",
        json_object_new_string(flow->ssh_tls.ja4_client[0] != '\0' ? flow->ssh_tls.ja4_client : ""));
    json_object_object_add(json_info_tls, "ja4_client_category",
        json_object_new_string(flow->ssh_tls.ja4_client[0] != '\0' ? is_unsafe_cipher(flow->ssh_tls.client_unsafe_cipher) : ""));

    json_object_object_add(json_info_tls, "ja4_r",
        json_object_new_string(flow->ssh_tls.ja4_client_raw != NULL ? flow->ssh_tls.ja4_client_raw : ""));
    json_object_object_add(json_info_tls, "server_info",
        json_object_new_string(flow->ssh_tls.server_info[0] != '\0' ? flow->ssh_tls.server_info : ""));
    json_object_object_add(json_info_tls, "server_names",
        json_object_new_string(flow->ssh_tls.server_names ? flow->ssh_tls.server_names : ""));
    json_object_object_add(json_info_tls, "server_hassh",
        json_object_new_string(flow->ssh_tls.server_hassh[0] != '\0' ? flow->ssh_tls.server_hassh : ""));

    json_object_object_add(json_info_tls, "ja3_server",
        json_object_new_string(flow->ssh_tls.ja3_server[0] != '\0' ? flow->ssh_tls.ja3_server : ""));
    json_object_object_add(json_info_tls, "ja3_server_category",
        json_object_new_string(
            flow->ssh_tls.ja3_server[0] != '\0' ? is_unsafe_cipher(flow->ssh_tls.server_unsafe_cipher) : ""));

    json_object_object_add(json_info_tls, "tls_issuer_dn",
        json_object_new_string(flow->ssh_tls.tls_issuerDN ? flow->ssh_tls.tls_issuerDN : ""));
    json_object_object_add(json_info_tls, "tls_subject_dn",
        json_object_new_string(flow->ssh_tls.tls_subjectDN ? flow->ssh_tls.tls_subjectDN : ""));

    json_object_object_add(json_info_tls, "esni",
        json_object_new_string(
            flow->ssh_tls.encrypted_sni.esni ? flow->ssh_tls.encrypted_sni.esni : ""));
    json_object_object_add(json_info_tls, "esni_cipher",
        json_object_new_string(
            flow->ssh_tls.encrypted_sni.esni ? ndpi_cipher2str(flow->ssh_tls.encrypted_sni.cipher_suite, unknown_cipher) : ""));

    json_object_object_add(json_info_tls, "ech_version",
        json_object_new_uint64(
            flow->ssh_tls.encrypted_ch.version != 0 ? (unsigned long long)flow->ssh_tls.encrypted_ch.version : 0));

    if (flow->ssh_tls.sha1_cert_fingerprint_set) {
        string_t sha1_cert = str_new("");
        string_t temp = str_new("");
        for (int i = 0; i < 20; i++) {
            sha1_cert = str_format("%s%s%02X",
                temp.content,
                (i > 0) ? ":" : "",
                flow->ssh_tls.sha1_cert_fingerprint[i] & 0xFF
            );
            str_delete(&temp);

            temp = sha1_cert;
        }
        json_object_object_add(json_info_tls, "sha1_cert",
            json_object_new_string(
                (const char*)sha1_cert.content));
        str_delete(&sha1_cert);
    }
    else {
        json_object_object_add(json_info_tls, "sha1_cert",
            json_object_new_string(""));
    }

#ifdef HEURISTICS_CODE
    json_object_object_add(json_info_tls, "is_safari_tls",
        json_object_new_boolean(flow->ssh_tls.browser_heuristics.is_safari_tls));
    json_object_object_add(json_info_tls, "is_firefox_tls",
        json_object_new_boolean(flow->ssh_tls.browser_heuristics.is_firefox_tls));
    json_object_object_add(json_info_tls, "is_chrome_tls",
        json_object_new_boolean(flow->ssh_tls.browser_heuristics.is_chrome_tls));
#endif
    if (flow->ssh_tls.notBefore && flow->ssh_tls.notAfter) {
        char notBefore[32], notAfter[32];
        struct tm a, b;
        struct tm* before = ndpi_gmtime_r(&flow->ssh_tls.notBefore, &a);
        struct tm* after = ndpi_gmtime_r(&flow->ssh_tls.notAfter, &b);

        strftime(notBefore, sizeof(notBefore), "%Y-%m-%d %H:%M:%S", before);
        strftime(notAfter, sizeof(notAfter), "%Y-%m-%d %H:%M:%S", after);

        json_object_object_add(json_info_tls, "validity_notbefore",
            json_object_new_string(notBefore));
        json_object_object_add(json_info_tls, "validity_notafter",
            json_object_new_string(notAfter));
    }
    else {
        json_object_object_add(json_info_tls, "validity_notbefore",
            json_object_new_string(""));
        json_object_object_add(json_info_tls, "validity_notafter",
            json_object_new_string(""));
    }

    json_object_object_add(json_info_tls, "cipher",
        json_object_new_string(
            flow->ssh_tls.server_cipher != '\0' ? ndpi_cipher2str(flow->ssh_tls.server_cipher, unknown_cipher) : ""));

    json_object_object_add(retval, "info_tls", json_info_tls);

    // Analytics if big enough
    json_object* json_info_analytics = json_object_new_object();
    if ((flow->src2dst_packets + flow->dst2src_packets) > 5) {
        if (flow->iat_c_to_s && flow->iat_s_to_c) {
            //--Inter Arrival Time
            json_object* json_info_inter_arrival_time = json_object_new_object();
            json_object* json_info_inter_arrival_time_server_client = json_object_new_object();
            json_object* json_info_inter_arrival_time_client_server = json_object_new_object();
            json_object_object_add(json_info_inter_arrival_time_server_client, "min",
                json_object_new_uint64((unsigned long long)ndpi_data_min(flow->iat_c_to_s)));
            json_object_object_add(json_info_inter_arrival_time_server_client, "avg",
                json_object_new_uint64((float)ndpi_data_average(flow->iat_c_to_s)));
            json_object_object_add(json_info_inter_arrival_time_server_client, "stddev",
                json_object_new_uint64((float)ndpi_data_stddev(flow->iat_c_to_s)));
            json_object_object_add(json_info_inter_arrival_time_server_client, "max",
                json_object_new_uint64((unsigned long long)ndpi_data_max(flow->iat_c_to_s)));
            json_object_object_add(json_info_inter_arrival_time, "server_client", json_info_inter_arrival_time_server_client);

            json_object_object_add(json_info_inter_arrival_time_client_server, "min",
                json_object_new_uint64((unsigned long long)ndpi_data_min(flow->iat_s_to_c)));
            json_object_object_add(json_info_inter_arrival_time_client_server, "avg",
                json_object_new_uint64((float)ndpi_data_average(flow->iat_s_to_c)));
            json_object_object_add(json_info_inter_arrival_time_client_server, "stddev",
                json_object_new_uint64((float)ndpi_data_stddev(flow->iat_s_to_c)));
            json_object_object_add(json_info_inter_arrival_time_client_server, "max",
                json_object_new_uint64((unsigned long long)ndpi_data_max(flow->iat_s_to_c)));
            json_object_object_add(json_info_inter_arrival_time, "client_server", json_info_inter_arrival_time_client_server);
            json_object_object_add(json_info_analytics, "inter_arrival_time", json_info_inter_arrival_time);

            //--Packet Length
            json_object* json_info_packet_length = json_object_new_object();
            json_object* json_info_packet_length_server_client = json_object_new_object();
            json_object* json_info_packet_length_client_server = json_object_new_object();
            json_object_object_add(json_info_packet_length_server_client, "min",
                json_object_new_uint64((unsigned long long)ndpi_data_min(flow->pktlen_c_to_s)));
            json_object_object_add(json_info_packet_length_server_client, "avg",
                json_object_new_uint64((float)ndpi_data_average(flow->pktlen_c_to_s)));
            json_object_object_add(json_info_packet_length_server_client, "stddev",
                json_object_new_uint64((float)ndpi_data_stddev(flow->pktlen_c_to_s)));
            json_object_object_add(json_info_packet_length_server_client, "max",
                json_object_new_uint64((unsigned long long)ndpi_data_max(flow->pktlen_c_to_s)));
            json_object_object_add(json_info_packet_length, "server_client", json_info_packet_length_server_client);

            json_object_object_add(json_info_packet_length_client_server, "min",
                json_object_new_uint64((unsigned long long)ndpi_data_min(flow->pktlen_s_to_c)));
            json_object_object_add(json_info_packet_length_client_server, "avg",
                json_object_new_uint64((float)ndpi_data_average(flow->pktlen_s_to_c)));
            json_object_object_add(json_info_packet_length_client_server, "stddev",
                json_object_new_uint64((float)ndpi_data_stddev(flow->pktlen_s_to_c)));
            json_object_object_add(json_info_packet_length_client_server, "max",
                json_object_new_uint64((unsigned long long)ndpi_data_max(flow->pktlen_s_to_c)));
            json_object_object_add(json_info_packet_length, "client_server", json_info_packet_length_client_server);
            json_object_object_add(json_info_analytics, "packet_length", json_info_packet_length);
        }
    }
    json_object_object_add(retval, "info_analytics", json_info_analytics);

    // HTTP
    json_object* json_info_http = json_object_new_object();
    json_object_object_add(json_info_http, "url",
        json_object_new_string(flow->http.url[0] != '\0' ? flow->http.url : ""));
    json_object_object_add(json_info_http, "response_status_code",
        json_object_new_uint64(flow->http.response_status_code ? (unsigned long long)flow->http.response_status_code : 0));
    json_object_object_add(json_info_http, "request_content_type",
        json_object_new_string(flow->http.request_content_type[0] != '\0' ? flow->http.request_content_type : ""));
    json_object_object_add(json_info_http, "content_type",
        json_object_new_string(flow->http.content_type[0] != '\0' ? flow->http.content_type : ""));
    json_object_object_add(json_info_http, "nat_ip",
        json_object_new_string(flow->http.nat_ip[0] != '\0' ? flow->http.nat_ip : ""));
    json_object_object_add(json_info_http, "server",
        json_object_new_string(flow->http.server[0] != '\0' ? flow->http.server : ""));
    json_object_object_add(json_info_http, "user_agent",
        json_object_new_string(flow->http.user_agent[0] != '\0' ? flow->http.user_agent : ""));
    json_object_object_add(json_info_http, "filename",
        json_object_new_string(flow->http.filename[0] != '\0' ? flow->http.filename : ""));
    json_object_object_add(retval, "info_http", json_info_http);

    // risk
    json_object* json_info_risk = json_object_new_object();
    if (flow->risk) {
        u_int i;
        u_int16_t cli_score, srv_score;

        json_object* json_risk_names = json_object_new_array();
        for (i = 0; i < NDPI_MAX_RISK; i++) {
            if (NDPI_ISSET_BIT(flow->risk, i)) {
                json_object_array_add(json_risk_names, json_object_new_string(ndpi_risk2str(i)));
            }
        }
        json_object_object_add(json_info_risk, "names", json_risk_names);
        json_object_object_add(json_info_risk, "score", json_object_new_uint64(ndpi_risk2score(flow->risk, &cli_score, &srv_score)));
        json_object_object_add(json_info_risk, "info",
            json_object_new_string(flow->risk_str ? flow->risk_str : ""));
    }
    json_object_object_add(retval, "info_risk", json_info_risk);

    // payload
    if (flow->flow_payload && (flow->flow_payload_len > 0)) {
        ILOG("Payload checking: %s; len: %d", flow->flow_payload, flow->flow_payload_len);
        string_t payload = str_new("");
        for (int i = 0; i < flow->flow_payload_len; i++) {
            str_addc(&payload, ndpi_isspace(flow->flow_payload[i]) ? '.' : flow->flow_payload[i]);
        }
        json_object_object_add(retval, "payload",
            json_object_new_string((const char*)payload.content));
        str_delete(&payload);
    }
    else {
        json_object_object_add(retval, "payload",
            json_object_new_string(""));
    }

    return retval;
}
