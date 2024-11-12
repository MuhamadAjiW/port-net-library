#include "../../include/lib-csv.h"

void csv_print_header(FILE* csv_fp, uint8_t enable_flow_stats) {
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

void csv_print_flow(FILE* csv_fp, struct ndpi_flow_info* flow, u_int16_t thread_id) {
    u_int8_t known_tls;
    char buf[32];
    char buf_ver[16];
    char buf2_ver[16];
    float data_ratio = ndpi_data_ratio(flow->src2dst_bytes, flow->dst2src_bytes);
    double f = (double)flow->first_seen_ms, l = (double)flow->last_seen_ms;

    fprintf(csv_fp, "%u|%u|%.3f|%.3f|%.3f|%s|%u|%s|%u|",
        flow->flow_id,
        flow->protocol,
        f / 1000.0, l / 1000.0,
        (l - f) / 1000.0,
        flow->src_name, ntohs(flow->src_port),
        flow->dst_name, ntohs(flow->dst_port)
    );

    fprintf(csv_fp, "%s|",
        ndpi_protocol2id(flow->detected_protocol, buf, sizeof(buf)));

    fprintf(csv_fp, "%s|%s|%s|",
        ndpi_protocol2name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
            flow->detected_protocol, buf, sizeof(buf)),
        ndpi_get_proto_name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
            flow->detected_protocol.protocol_by_ip),
        flow->host_server_name);

    fprintf(csv_fp, "%u|%llu|%llu|", flow->src2dst_packets,
        (long long unsigned int) flow->src2dst_bytes, (long long unsigned int) flow->src2dst_goodput_bytes);
    fprintf(csv_fp, "%u|%llu|%llu|", flow->dst2src_packets,
        (long long unsigned int) flow->dst2src_bytes, (long long unsigned int) flow->dst2src_goodput_bytes);
    fprintf(csv_fp, "%.3f|%s|", data_ratio, ndpi_data_ratio2str(data_ratio));
    fprintf(csv_fp, "%.1f|%.1f|", 100.0 * ((float)flow->src2dst_goodput_bytes / (float)(flow->src2dst_bytes + 1)),
        100.0 * ((float)flow->dst2src_goodput_bytes / (float)(flow->dst2src_bytes + 1)));

/* IAT (Inter Arrival Time) */
    fprintf(csv_fp, "%llu|%.1f|%llu|%.1f|",
        (unsigned long long int)ndpi_data_min(flow->iat_flow), ndpi_data_average(flow->iat_flow),
        (unsigned long long int)ndpi_data_max(flow->iat_flow), ndpi_data_stddev(flow->iat_flow));

    fprintf(csv_fp, "%llu|%.1f|%llu|%.1f|%llu|%.1f|%llu|%.1f|",
        (unsigned long long int)ndpi_data_min(flow->iat_c_to_s), ndpi_data_average(flow->iat_c_to_s),
        (unsigned long long int)ndpi_data_max(flow->iat_c_to_s), ndpi_data_stddev(flow->iat_c_to_s),
        (unsigned long long int)ndpi_data_min(flow->iat_s_to_c), ndpi_data_average(flow->iat_s_to_c),
        (unsigned long long int)ndpi_data_max(flow->iat_s_to_c), ndpi_data_stddev(flow->iat_s_to_c));

    /* Packet Length */
    fprintf(csv_fp, "%llu|%.1f|%llu|%.1f|%llu|%.1f|%llu|%.1f|",
        (unsigned long long int)ndpi_data_min(flow->pktlen_c_to_s), ndpi_data_average(flow->pktlen_c_to_s),
        (unsigned long long int)ndpi_data_max(flow->pktlen_c_to_s), ndpi_data_stddev(flow->pktlen_c_to_s),
        (unsigned long long int)ndpi_data_min(flow->pktlen_s_to_c), ndpi_data_average(flow->pktlen_s_to_c),
        (unsigned long long int)ndpi_data_max(flow->pktlen_s_to_c), ndpi_data_stddev(flow->pktlen_s_to_c));

    /* TCP flags */
    fprintf(csv_fp, "%d|%d|%d|%d|%d|%d|%d|%d|", flow->cwr_count, flow->ece_count, flow->urg_count, flow->ack_count, flow->psh_count, flow->rst_count, flow->syn_count, flow->fin_count);

    fprintf(csv_fp, "%d|%d|%d|%d|%d|%d|%d|%d|", flow->src2dst_cwr_count, flow->src2dst_ece_count, flow->src2dst_urg_count, flow->src2dst_ack_count,
        flow->src2dst_psh_count, flow->src2dst_rst_count, flow->src2dst_syn_count, flow->src2dst_fin_count);

    fprintf(csv_fp, "%d|%d|%d|%d|%d|%d|%d|%d|", flow->dst2src_cwr_count, flow->dst2src_ece_count, flow->dst2src_urg_count, flow->dst2src_ack_count,
        flow->dst2src_psh_count, flow->dst2src_rst_count, flow->dst2src_syn_count, flow->dst2src_fin_count);

    /* TCP window */
    fprintf(csv_fp, "%u|%u|", flow->c_to_s_init_win, flow->s_to_c_init_win);

    fprintf(csv_fp, "%s|",
        (flow->ssh_tls.server_info[0] != '\0') ? flow->ssh_tls.server_info : "");

    fprintf(csv_fp, "%s|%s|%s|%s|%s|%s|",
        (flow->ssh_tls.ssl_version != 0) ? ndpi_ssl_version2str(buf_ver, sizeof(buf_ver), flow->ssh_tls.ssl_version, &known_tls) : "0",
        (flow->ssh_tls.quic_version != 0) ? ndpi_quic_version2str(buf2_ver, sizeof(buf2_ver), flow->ssh_tls.quic_version) : "0",
        (flow->ssh_tls.ja3_client[0] != '\0') ? flow->ssh_tls.ja3_client : "",
        (flow->ssh_tls.ja3_client[0] != '\0') ? is_unsafe_cipher(flow->ssh_tls.client_unsafe_cipher) : "0",
        (flow->ssh_tls.ja3_server[0] != '\0') ? flow->ssh_tls.ja3_server : "",
        (flow->ssh_tls.ja3_server[0] != '\0') ? is_unsafe_cipher(flow->ssh_tls.server_unsafe_cipher) : "0");

    fprintf(csv_fp, "%s|%s|%s|",
        flow->ssh_tls.advertised_alpns ? flow->ssh_tls.advertised_alpns : "",
        flow->ssh_tls.negotiated_alpn ? flow->ssh_tls.negotiated_alpn : "",
        flow->ssh_tls.tls_supported_versions ? flow->ssh_tls.tls_supported_versions : ""
    );

#if 0
    fprintf(csv_fp, "%s|%s|",
        flow->ssh_tls.tls_issuerDN ? flow->ssh_tls.tls_issuerDN : "",
        flow->ssh_tls.tls_subjectDN ? flow->ssh_tls.tls_subjectDN : ""
    );
#endif

    fprintf(csv_fp, "%s|%s",
        (flow->ssh_tls.client_hassh[0] != '\0') ? flow->ssh_tls.client_hassh : "",
        (flow->ssh_tls.server_hassh[0] != '\0') ? flow->ssh_tls.server_hassh : ""
    );

    fprintf(csv_fp, "|%s|", flow->info);

#ifndef DIRECTION_BINS
    // _TODO: Separate printing and csv printing
    // print_bin(csv_fp, NULL, &flow->payload_len_bin);
#endif

    fprintf(csv_fp, "|%s", flow->http.user_agent);

    if ((verbose != 1) && (verbose != 2)) {
        if (csv_fp && enable_flow_stats) {
            flowGetBDMeanandVariance(flow);
        }

        if (csv_fp)
            fprintf(csv_fp, "\n");
              //  return;
    }
}