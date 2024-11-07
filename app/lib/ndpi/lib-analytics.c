#include "../../include/lib-analytics.h"

/* *********************************************** */
// Analytical functions

double ndpi_flow_get_byte_count_entropy(const uint32_t byte_count[256], unsigned int num_bytes) {
    int i;
    double sum = 0.0;

    for (i = 0; i < 256; i++) {
        double tmp = (double)byte_count[i] / (double)num_bytes;

        if (tmp > FLT_EPSILON) {
            sum -= tmp * logf(tmp);
        }
    }
    return(sum / log(2.0));
}

u_int check_bin_doh_similarity(struct ndpi_bin* bin, float* similarity) {
    u_int i;
    float lowest_similarity = 9999999999.0f;

    for (i = 0; i < NUM_DOH_BINS; i++) {
        *similarity = ndpi_bin_similarity(&doh_ndpi_bins[i], bin, 0, 0);

        if (*similarity < 0) /* Error */
            return(0);

        if (*similarity <= doh_max_distance)
            return(1);

        if (*similarity < lowest_similarity) lowest_similarity = *similarity;
    }

    *similarity = lowest_similarity;

    return(0);
}

void flowGetBDMeanandVariance(struct ndpi_flow_info* flow) {
    FILE* out = results_file ? results_file : stdout;
    const uint32_t* array = NULL;
    uint32_t tmp[256], i;
    unsigned int num_bytes;
    double mean = 0.0, variance = 0.0;
    struct ndpi_entropy* last_entropy = flow->last_entropy;

    fflush(out);

    if (!last_entropy)
        return;

      /*
       * Sum up the byte_count array for outbound and inbound flows,
       * if this flow is bidirectional
       */
      /* TODO: we could probably use ndpi_data_* generic functions to simplify the code and
         to get rid of `ndpi_flow_get_byte_count_entropy()` */
    if (!flow->bidirectional) {
        array = last_entropy->src2dst_byte_count;
        num_bytes = last_entropy->src2dst_l4_bytes;
        for (i = 0; i < 256; i++) {
            tmp[i] = last_entropy->src2dst_byte_count[i];
        }

        if (last_entropy->src2dst_num_bytes != 0) {
            mean = last_entropy->src2dst_bd_mean;
            variance = last_entropy->src2dst_bd_variance / (last_entropy->src2dst_num_bytes - 1);
            variance = sqrt(variance);

            if (last_entropy->src2dst_num_bytes == 1) {
                variance = 0.0;
            }
        }
    }
    else {
        for (i = 0; i < 256; i++) {
            tmp[i] = last_entropy->src2dst_byte_count[i] + last_entropy->dst2src_byte_count[i];
        }
        array = tmp;
        num_bytes = last_entropy->src2dst_l4_bytes + last_entropy->dst2src_l4_bytes;

        if (last_entropy->src2dst_num_bytes + last_entropy->dst2src_num_bytes != 0) {
            mean = ((double)last_entropy->src2dst_num_bytes) / ((double)(last_entropy->src2dst_num_bytes + last_entropy->dst2src_num_bytes)) * last_entropy->src2dst_bd_mean +
                ((double)last_entropy->dst2src_num_bytes) / ((double)(last_entropy->dst2src_num_bytes + last_entropy->src2dst_num_bytes)) * last_entropy->dst2src_bd_mean;

            variance = ((double)last_entropy->src2dst_num_bytes) / ((double)(last_entropy->src2dst_num_bytes + last_entropy->dst2src_num_bytes)) * last_entropy->src2dst_bd_variance +
                ((double)last_entropy->dst2src_num_bytes) / ((double)(last_entropy->dst2src_num_bytes + last_entropy->src2dst_num_bytes)) * last_entropy->dst2src_bd_variance;

            variance = variance / ((double)(last_entropy->src2dst_num_bytes + last_entropy->dst2src_num_bytes - 1));
            variance = sqrt(variance);
            if (last_entropy->src2dst_num_bytes + last_entropy->dst2src_num_bytes == 1) {
                variance = 0.0;
            }
        }
    }

    if (enable_flow_stats) {
      /* Output the mean */
        if (num_bytes != 0) {
            double entropy = ndpi_flow_get_byte_count_entropy(array, num_bytes);

            if (csv_fp) {
                fprintf(csv_fp, "|%.3f|%.3f|%.3f|%.3f", mean, variance, entropy, entropy * num_bytes);
            }
            else {
                fprintf(out, "[byte_dist_mean: %.3f", mean);
                fprintf(out, "][byte_dist_std: %.3f]", variance);
                fprintf(out, "[entropy: %.3f]", entropy);
                fprintf(out, "[total_entropy: %.3f]", entropy * num_bytes);
            }
        }
        else {
            if (csv_fp)
                fprintf(csv_fp, "|%.3f|%.3f|%.3f|%.3f", 0.0, 0.0, 0.0, 0.0);
        }
    }
}

/* *********************************************** */
// Walkers

void node_proto_guess_walker(const void* node, ndpi_VISIT which, int depth, void* user_data) {
    struct ndpi_flow_info* flow = *(struct ndpi_flow_info**)node;
    u_int16_t thread_id = *((u_int16_t*)user_data), proto;

    (void)depth;

    if (flow == NULL) return;

    if ((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
        if ((!flow->detection_completed) && flow->ndpi_flow) {
            u_int8_t proto_guessed;

            malloc_size_stats = 1;
            flow->detected_protocol = ndpi_detection_giveup(ndpi_thread_info[0].workflow->ndpi_struct,
                flow->ndpi_flow, &proto_guessed);
            malloc_size_stats = 0;

            if (proto_guessed) ndpi_thread_info[thread_id].workflow->stats.guessed_flow_protocols++;
        }

        process_ndpi_collected_info(ndpi_thread_info[thread_id].workflow, flow);

        proto = flow->detected_protocol.proto.app_protocol ? flow->detected_protocol.proto.app_protocol : flow->detected_protocol.proto.master_protocol;

        proto = ndpi_map_user_proto_id_to_ndpi_id(ndpi_thread_info[thread_id].workflow->ndpi_struct, proto);

        ndpi_thread_info[thread_id].workflow->stats.protocol_counter[proto] += flow->src2dst_packets + flow->dst2src_packets;
        ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes[proto] += flow->src2dst_bytes + flow->dst2src_bytes;
        ndpi_thread_info[thread_id].workflow->stats.protocol_flows[proto]++;
        ndpi_thread_info[thread_id].workflow->stats.flow_confidence[flow->confidence]++;
        ndpi_thread_info[thread_id].workflow->stats.num_dissector_calls += flow->num_dissector_calls;
    }
}

void node_flow_risk_walker(const void* node, ndpi_VISIT which, int depth, void* user_data) {
    struct ndpi_flow_info* f = *(struct ndpi_flow_info**)node;

    (void)depth;
    (void)user_data;

    if ((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
        if (f->risk) {
            u_int j;

            flows_with_risks++;

            for (j = 0; j < NDPI_MAX_RISK; j++) {
                ndpi_risk_enum r = (ndpi_risk_enum)j;

                if (NDPI_ISSET_BIT(f->risk, r)) {
                    risks_found++, risk_stats[r]++;
                }
            }
        }
    }
}

void node_proto_print_walker(const void* node,
    ndpi_VISIT which, int depth, void* user_data) {
    struct flow_info info;
    info.thread_id = *((u_int16_t*)user_data);
    info.flow = *(struct ndpi_flow_info**)node;

    (void)depth;

    if ((which == ndpi_preorder) || (which == ndpi_leaf)) {
        /* Avoid walking the same node multiple times */

        if ((info.flow->detected_protocol.proto.master_protocol != NDPI_PROTOCOL_UNKNOWN)
            || (info.flow->detected_protocol.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN))
        {
            dynarray_push_back(&global_data.known_flow, &info);
        }
        else {
            dynarray_push_back(&global_data.unknown_flow, &info);
        }
    }
}

/* *********************************************** */

void global_data_init() {
    dynarray_init(&global_data.protocol, sizeof(struct data_protocol));
    dynarray_init(&global_data.classification, sizeof(struct data_classification));
    dynarray_init(&global_data.risk, sizeof(struct data_risk));
    dynarray_init(&global_data.known_flow, sizeof(struct flow_info));
    dynarray_init(&global_data.unknown_flow, sizeof(struct flow_info));
}

void global_data_clean() {
    struct data_protocol* protocol_array = global_data.protocol.content;
    struct data_classification* classification_array = global_data.classification.content;
    struct data_risk* risk_array = global_data.risk.content;

    DLOG(TAG_DATA, "Cleaning classification data, length %d", global_data.classification.length);
    for (size_t i = 0; i < global_data.classification.length; i++) {
        data_classification_clean(&classification_array[i]);
    }
    DLOG(TAG_DATA, "Cleaning protocol data, length %d", global_data.protocol.length);
    for (size_t i = 0; i < global_data.protocol.length; i++) {
        data_protocol_clean(&protocol_array[i]);
    }
    DLOG(TAG_DATA, "Cleaning risk data, length %d", global_data.risk.length);
    for (size_t i = 0; i < global_data.risk.length; i++) {
        data_risk_clean(&risk_array[i]);
    }

    dynarray_delete(&global_data.protocol);
    dynarray_delete(&global_data.classification);
    dynarray_delete(&global_data.risk);
    dynarray_delete(&global_data.known_flow);
    dynarray_delete(&global_data.unknown_flow);
    memset(&global_data, 0, sizeof(global_data));
}

void global_data_generate(
    uint64_t processing_time_usec,
    uint64_t setup_time_usec
) {
    global_data_clean();
    global_data_init();
    global_data_generate_memory();
    global_data_generate_traffic(processing_time_usec);
    global_data_generate_time(processing_time_usec, setup_time_usec);
    global_data_generate_detail();
    global_data_generate_protocol();
    global_data_generate_risk();
    global_data_generate_flow();
    global_data_reset_counters();
}

void global_data_reset_counters() {
    DLOG(TAG_DATA, "resetting global data counters");
    // Traffic counters
    for (int thread_id = 0; thread_id < num_threads; thread_id++) {
        memset(ndpi_thread_info[thread_id].workflow->stats.protocol_counter, 0, sizeof(ndpi_thread_info[thread_id].workflow->stats.protocol_counter));
        memset(ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes, 0, sizeof(ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes));
        memset(ndpi_thread_info[thread_id].workflow->stats.protocol_flows, 0, sizeof(ndpi_thread_info[thread_id].workflow->stats.protocol_flows));
        memset(ndpi_thread_info[thread_id].workflow->stats.flow_confidence, 0, sizeof(ndpi_thread_info[thread_id].workflow->stats.flow_confidence));
        ndpi_thread_info[thread_id].workflow->stats.guessed_flow_protocols = 0;
        ndpi_thread_info[thread_id].workflow->stats.num_dissector_calls = 0;
    }

    // Risk counters
    memset(risk_stats, 0, sizeof(risk_stats));
    flows_with_risks = 0;
    risks_found = 0;
}

void global_data_generate_memory() {
    DLOG(TAG_DATA, "fetching memory to global data");
    global_data.memory.mem_once = ndpi_get_ndpi_detection_module_size();
    global_data.memory.mem_per_flow = ndpi_detection_get_sizeof_ndpi_flow_struct();
    global_data.memory.mem_actual = current_ndpi_memory;
    global_data.memory.mem_peak = max_ndpi_memory;
}

void global_data_generate_traffic(uint64_t processing_time_usec) {
    DLOG(TAG_DATA, "fetching traffic to global data");

    for (int thread_id = 0; thread_id < num_threads; thread_id++) {
        if ((ndpi_thread_info[thread_id].workflow->stats.total_wire_bytes == 0)
            && (ndpi_thread_info[thread_id].workflow->stats.raw_packet_count == 0))
            continue;

        for (int i = 0; i < NUM_ROOTS; i++) {
            ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
                node_proto_guess_walker, &thread_id);
            if (verbose == 3 || stats_flag) ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
                port_stats_walker, &thread_id);
        }

        /* Stats aggregation */
        global_data.traffic.guessed_flow_protocols += ndpi_thread_info[thread_id].workflow->stats.guessed_flow_protocols;
        global_data.traffic.raw_packet_count += ndpi_thread_info[thread_id].workflow->stats.raw_packet_count;
        global_data.traffic.ip_packet_count += ndpi_thread_info[thread_id].workflow->stats.ip_packet_count;
        global_data.traffic.total_wire_bytes += ndpi_thread_info[thread_id].workflow->stats.total_wire_bytes;
        global_data.traffic.total_ip_bytes += ndpi_thread_info[thread_id].workflow->stats.total_ip_bytes;
        global_data.traffic.total_discarded_bytes += ndpi_thread_info[thread_id].workflow->stats.total_discarded_bytes;
        global_data.traffic.ndpi_flow_count += ndpi_thread_info[thread_id].workflow->stats.ndpi_flow_count;
        global_data.traffic.dpi_flow_count[0] += ndpi_thread_info[thread_id].workflow->stats.flow_count[0];
        global_data.traffic.dpi_flow_count[1] += ndpi_thread_info[thread_id].workflow->stats.flow_count[1];
        global_data.traffic.dpi_flow_count[2] += ndpi_thread_info[thread_id].workflow->stats.flow_count[2];
        global_data.traffic.tcp_count += ndpi_thread_info[thread_id].workflow->stats.tcp_count;
        global_data.traffic.udp_count += ndpi_thread_info[thread_id].workflow->stats.udp_count;
        global_data.traffic.mpls_count += ndpi_thread_info[thread_id].workflow->stats.mpls_count;
        global_data.traffic.pppoe_count += ndpi_thread_info[thread_id].workflow->stats.pppoe_count;
        global_data.traffic.vlan_count += ndpi_thread_info[thread_id].workflow->stats.vlan_count;
        global_data.traffic.fragmented_count += ndpi_thread_info[thread_id].workflow->stats.fragmented_count;
        for (uint32_t i = 0; i < PACKET_LENGTH_CLASSIFICATION_COUNT; i++) {
            global_data.traffic.packet_len[i] += ndpi_thread_info[thread_id].workflow->stats.packet_len[i];
        }
        global_data.traffic.max_packet_len += ndpi_thread_info[thread_id].workflow->stats.max_packet_len;

        global_data.traffic.dpi_packet_count[0] += ndpi_thread_info[thread_id].workflow->stats.dpi_packet_count[0];
        global_data.traffic.dpi_packet_count[1] += ndpi_thread_info[thread_id].workflow->stats.dpi_packet_count[1];
        global_data.traffic.dpi_packet_count[2] += ndpi_thread_info[thread_id].workflow->stats.dpi_packet_count[2];

        for (uint32_t i = 0; i < NDPI_CONFIDENCE_MAX; i++) {
            global_data.traffic.flow_confidence[i] += ndpi_thread_info[thread_id].workflow->stats.flow_confidence[i];
        }

        global_data.traffic.num_dissector_calls += ndpi_thread_info[thread_id].workflow->stats.num_dissector_calls;
    }

    if (global_data.traffic.total_ip_bytes && global_data.traffic.raw_packet_count) {
        global_data.traffic.avg_pkt_size = (unsigned int)(global_data.traffic.total_ip_bytes / global_data.traffic.raw_packet_count);
    }
    else {
        global_data.traffic.avg_pkt_size = 0;
    }

    if (processing_time_usec > 0) {
        float t = (float)(global_data.traffic.ip_packet_count * 1000000) / (float)processing_time_usec;
        float b = (float)(global_data.traffic.total_wire_bytes * 8 * 1000000) / (float)processing_time_usec;

        global_data.traffic.ndpi_packets_per_second = t;
        global_data.traffic.ndpi_bytes_per_second = b;
        global_data.traffic.start_time = (long)pcap_start.tv_sec;
        global_data.traffic.end_time = (long)pcap_end.tv_sec;

        if (live_capture) {
            global_data.traffic.traffic_duration = processing_time_usec;
        }
        else {
            global_data.traffic.traffic_duration =
                ((u_int64_t)pcap_end.tv_sec * 1000000 + pcap_end.tv_usec) - ((u_int64_t)pcap_start.tv_sec * 1000000 + pcap_start.tv_usec);
        }

        if (global_data.traffic.traffic_duration != 0) {
            t = (float)(global_data.traffic.ip_packet_count * 1000000) / global_data.traffic.traffic_duration;
            b = (float)(global_data.traffic.total_wire_bytes * 8 * 1000000) / global_data.traffic.traffic_duration;
        }
        else {
            t = 0;
            b = 0;
        }

        global_data.traffic.traffic_packets_per_second = t;
        global_data.traffic.traffic_bytes_per_second = b;
    }
}


void global_data_generate_time(
    uint64_t processing_time_usec,
    uint64_t setup_time_usec
) {
    global_data.time.setup_time = (unsigned long)(setup_time_usec / 1000);
    global_data.time.processing_time = (unsigned long)(processing_time_usec / 1000);
}

void global_data_generate_risk() {
    DLOG(TAG_DATA, "fetching risk to global data");

    for (uint8_t thread_id = 0; thread_id < num_threads; thread_id++) {
        for (int i = 0; i < NUM_ROOTS; i++) {
            ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
                node_flow_risk_walker, &thread_id);
        }
    }

    if (risks_found) {
        struct data_risk temp_risk;
        for (int i = 0; i < NDPI_MAX_RISK; i++) {
            ndpi_risk_enum r = (ndpi_risk_enum)i;

            if (risk_stats[r] != 0) {
                data_risk_get(
                    &temp_risk,
                    (char*)ndpi_risk2str(r),
                    risk_stats[r],
                    (float)(risk_stats[r] * 100) / (float)risks_found
                );

                dynarray_push_back(&global_data.risk, (void*)&temp_risk);
            }
        }
    }

    global_data.risky_flow_count = flows_with_risks;
}

void global_data_generate_detail() {
    DLOG(TAG_DATA, "fetching detail to global data");
    char buf[32];

    for (uint8_t thread_id = 0; thread_id < num_threads; thread_id++) {
        /* LRU caches */
        for (uint32_t i = 0; i < NDPI_LRUCACHE_MAX; i++) {
            struct ndpi_lru_cache_stats s;
            int scope;
            char param[64];

            snprintf(param, sizeof(param), "lru.%s.scope", ndpi_lru_cache_idx_to_name(i));
            if (ndpi_get_config(ndpi_thread_info[thread_id].workflow->ndpi_struct, NULL, param, buf, sizeof(buf)) != NULL) {
                scope = atoi(buf);
                if (scope == NDPI_LRUCACHE_SCOPE_LOCAL ||
                    (scope == NDPI_LRUCACHE_SCOPE_GLOBAL && thread_id == 0)) {
                    ndpi_get_lru_cache_stats(ndpi_thread_info[thread_id].workflow->g_ctx,
                        ndpi_thread_info[thread_id].workflow->ndpi_struct, i, &s);
                    global_data.detail.lru_stats[i].n_insert += s.n_insert;
                    global_data.detail.lru_stats[i].n_search += s.n_search;
                    global_data.detail.lru_stats[i].n_found += s.n_found;
                }
            }
        }

        /* Automas */
        for (uint32_t i = 0; i < NDPI_AUTOMA_MAX; i++) {
            struct ndpi_automa_stats s;
            ndpi_get_automa_stats(ndpi_thread_info[thread_id].workflow->ndpi_struct, i, &s);
            global_data.detail.automa_stats[i].n_search += s.n_search;
            global_data.detail.automa_stats[i].n_found += s.n_found;
        }

        /* Patricia trees */
        for (uint32_t i = 0; i < NDPI_PTREE_MAX; i++) {
            struct ndpi_patricia_tree_stats s;
            ndpi_get_patricia_stats(ndpi_thread_info[thread_id].workflow->ndpi_struct, i, &s);
            global_data.detail.patricia_stats[i].n_search += s.n_search;
            global_data.detail.patricia_stats[i].n_found += s.n_found;
        }
    }
}

void global_data_generate_protocol() {
    DLOG(TAG_DATA, "fetching protocol to global data");
    struct ndpi_detection_module_struct* ndpi_dm_struct = ndpi_thread_info[0].workflow->ndpi_struct;
    struct data_classification temp_classification;
    struct data_protocol temp_protocol;

    long long unsigned int breed_stats_pkts[NUM_BREEDS] = { 0 };
    long long unsigned int breed_stats_bytes[NUM_BREEDS] = { 0 };
    long long unsigned int breed_stats_flows[NUM_BREEDS] = { 0 };

    u_int64_t protocol_counter[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1] = { 0 };
    u_int64_t protocol_counter_bytes[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1] = { 0 };
    u_int32_t protocol_flows[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1] = { 0 };

    for (int thread_id = 0; thread_id < num_threads; thread_id++) {
        for (uint32_t i = 0; i < ndpi_get_num_supported_protocols(ndpi_dm_struct); i++) {
            protocol_counter[i] += ndpi_thread_info[thread_id].workflow->stats.protocol_counter[i];
            protocol_counter_bytes[i] += ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes[i];
            protocol_flows[i] += ndpi_thread_info[thread_id].workflow->stats.protocol_flows[i];
        }
    }

    for (uint32_t i = 0; i <= ndpi_get_num_supported_protocols(ndpi_dm_struct); i++) {
        uint16_t user_proto_id = ndpi_map_ndpi_id_to_user_proto_id(ndpi_dm_struct, i);
        ndpi_protocol_breed_t breed = ndpi_get_proto_breed(ndpi_dm_struct, user_proto_id);

        if (protocol_counter[i] > 0) {
            breed_stats_bytes[breed] += (long long unsigned int)protocol_counter_bytes[i];
            breed_stats_pkts[breed] += (long long unsigned int)protocol_counter[i];
            breed_stats_flows[breed] += (long long unsigned int)protocol_flows[i];

            data_protocol_get(
                &temp_protocol,
                ndpi_get_proto_name(ndpi_thread_info[0].workflow->ndpi_struct, user_proto_id),
                (long long unsigned int)protocol_counter[i],
                (long long unsigned int)protocol_counter_bytes[i],
                protocol_flows[i]
            );

            dynarray_push_back(&global_data.protocol, (void*)&temp_protocol);
        }
    }

    for (uint32_t i = 0; i < NUM_BREEDS; i++) {
        if (breed_stats_pkts[i] > 0) {
            data_classification_get(
                &temp_classification,
                ndpi_get_proto_breed_name(i),
                breed_stats_pkts[i],
                breed_stats_bytes[i],
                breed_stats_flows[i]
            );

            dynarray_push_back(&global_data.classification, (void*)&temp_classification);
        }
    }
}

void global_data_generate_flow() {
    for (int thread_id = 0; thread_id < num_threads; thread_id++) {
        for (int i = 0; i < NUM_ROOTS; i++) {
            ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
                node_proto_print_walker, &thread_id);
        }
    }
}

/* *********************************************** */

void* global_data_send(__attribute__((unused)) void* args) {
    struct data_protocol* protocol_array = global_data.protocol.content;
    struct data_classification* classification_array = global_data.classification.content;
    struct data_risk* risk_array = global_data.risk.content;

    json_object* json_memory = data_memory_to_json(&global_data.memory);
    json_object* json_time = data_time_to_json(&global_data.time);
    json_object* json_traffic = data_traffic_to_json(&global_data.traffic);

    json_object* json_protocol = json_object_new_object();
    json_object* json_protocol_array = json_object_new_array();
    for (size_t i = 0; i < global_data.protocol.length; i++) {
        json_object* json_protocol_entry = data_protocol_to_json(&protocol_array[i]);
        json_object_array_add(json_protocol_array, json_protocol_entry);
    }
    json_object_object_add(json_protocol, "protocols", json_protocol_array);

    json_object* json_classification = json_object_new_object();
    json_object* json_classification_array = json_object_new_array();
    for (size_t i = 0; i < global_data.classification.length; i++) {
        json_object* json_classification_entry = data_classification_to_json(&classification_array[i]);
        json_object_array_add(json_classification_array, json_classification_entry);
    }
    json_object_object_add(json_classification, "classifications", json_classification_array);

    json_object* json_risk = json_object_new_object();
    json_object* json_risk_array = json_object_new_array();
    for (size_t i = 0; i < global_data.risk.length; i++) {
        json_object* json_risk_entry = data_risk_to_json(&risk_array[i]);
        json_object_array_add(json_risk_array, json_risk_entry);
    }
    json_object_object_add(json_risk, "risks", json_risk_array);


    lzmq_send_json(
        &global_zmq_data_conn,
        json_memory,
        0
    );
    lzmq_send_json(
        &global_zmq_data_conn,
        json_time,
        0
    );
    lzmq_send_json(
        &global_zmq_data_conn,
        json_traffic,
        0
    );
    lzmq_send_json(
        &global_zmq_data_conn,
        json_protocol,
        0
    );
    lzmq_send_json(
        &global_zmq_data_conn,
        json_classification,
        0
    );
    lzmq_send_json(
        &global_zmq_data_conn,
        json_risk,
        0
    );

    json_object_put(json_memory);
    json_object_put(json_time);
    json_object_put(json_traffic);
    json_object_put(json_protocol);
    json_object_put(json_classification);
    json_object_put(json_risk);

    return NULL;
}

void* global_flow_send(__attribute__((unused)) void* args) {
    struct flow_info* known_flow_array = global_data.known_flow.content;
    struct flow_info* unknown_flow_array = global_data.unknown_flow.content;
    json_object* json_flow = json_object_new_object();

    json_object* json_known_flow_array = json_object_new_array();
    for (size_t i = 0; i < global_data.known_flow.length; i++) {
        json_object* json_known_flow_entry = data_flow_to_json(&known_flow_array[i]);
        json_object_array_add(json_known_flow_array, json_known_flow_entry);
    }

    json_object* json_unknown_flow_array = json_object_new_array();
    for (size_t i = 0; i < global_data.unknown_flow.length; i++) {
        json_object* json_unknown_flow_entry = data_flow_to_json(&unknown_flow_array[i]);
        json_object_array_add(json_unknown_flow_array, json_unknown_flow_entry);
    }
    json_object_object_add(json_flow, "known_flows", json_known_flow_array);
    json_object_object_add(json_flow, "unknown_flows", json_unknown_flow_array);

    lzmq_send_json(
        &global_zmq_flow_conn,
        json_flow,
        0
    );

    json_object_put(json_flow);

    return NULL;
}