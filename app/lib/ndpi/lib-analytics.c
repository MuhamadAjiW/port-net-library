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

                if (NDPI_ISSET_BIT(f->risk, r))
                    risks_found++, risk_stats[r]++;
            }
        }
    }
}

void node_print_known_proto_walker(const void* node,
    ndpi_VISIT which, int depth, void* user_data) {
    struct ndpi_flow_info* flow = *(struct ndpi_flow_info**)node;
    u_int16_t thread_id = *((u_int16_t*)user_data);

    (void)depth;

    if ((flow->detected_protocol.proto.master_protocol == NDPI_PROTOCOL_UNKNOWN)
        && (flow->detected_protocol.proto.app_protocol == NDPI_PROTOCOL_UNKNOWN))
        return;

    if ((which == ndpi_preorder) || (which == ndpi_leaf)) {
      /* Avoid walking the same node multiple times */
        all_flows[num_flows].thread_id = thread_id, all_flows[num_flows].flow = flow;
        num_flows++;
    }
}

void node_print_unknown_proto_walker(const void* node,
    ndpi_VISIT which, int depth, void* user_data) {
    struct ndpi_flow_info* flow = *(struct ndpi_flow_info**)node;
    u_int16_t thread_id = *((u_int16_t*)user_data);

    (void)depth;

    if ((flow->detected_protocol.proto.master_protocol != NDPI_PROTOCOL_UNKNOWN)
        || (flow->detected_protocol.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN))
        return;

    if ((which == ndpi_preorder) || (which == ndpi_leaf)) {
      /* Avoid walking the same node multiple times */
        all_flows[num_flows].thread_id = thread_id, all_flows[num_flows].flow = flow;
        num_flows++;
    }
}
