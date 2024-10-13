
#include "../../include/lib-print-ncurses.h"

// Print result to an ncurses window
void ncurses_printResults(uint64_t processing_time_usec, uint64_t setup_time_usec) {
    u_int32_t i;
    u_int32_t avg_pkt_size = 0;
    int thread_id;
    char buf[32];
    long long unsigned int breed_stats_pkts[NUM_BREEDS] = { 0 };
    long long unsigned int breed_stats_bytes[NUM_BREEDS] = { 0 };
    long long unsigned int breed_stats_flows[NUM_BREEDS] = { 0 };

    memset(&cumulative_stats, 0, sizeof(cumulative_stats));

    for (thread_id = 0; thread_id < num_threads; thread_id++) {
        if ((ndpi_thread_info[thread_id].workflow->stats.total_wire_bytes == 0)
            && (ndpi_thread_info[thread_id].workflow->stats.raw_packet_count == 0))
            continue;

        for (i = 0; i < NUM_ROOTS; i++) {
            ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
                node_proto_guess_walker, &thread_id);
            if (verbose == 3 || stats_flag) ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
                port_stats_walker, &thread_id);
        }

        /* Stats aggregation */
        cumulative_stats.guessed_flow_protocols += ndpi_thread_info[thread_id].workflow->stats.guessed_flow_protocols;
        cumulative_stats.raw_packet_count += ndpi_thread_info[thread_id].workflow->stats.raw_packet_count;
        cumulative_stats.ip_packet_count += ndpi_thread_info[thread_id].workflow->stats.ip_packet_count;
        cumulative_stats.total_wire_bytes += ndpi_thread_info[thread_id].workflow->stats.total_wire_bytes;
        cumulative_stats.total_ip_bytes += ndpi_thread_info[thread_id].workflow->stats.total_ip_bytes;
        cumulative_stats.total_discarded_bytes += ndpi_thread_info[thread_id].workflow->stats.total_discarded_bytes;

        for (i = 0; i < ndpi_get_num_supported_protocols(ndpi_thread_info[0].workflow->ndpi_struct); i++) {
            cumulative_stats.protocol_counter[i] += ndpi_thread_info[thread_id].workflow->stats.protocol_counter[i];
            cumulative_stats.protocol_counter_bytes[i] += ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes[i];
            cumulative_stats.protocol_flows[i] += ndpi_thread_info[thread_id].workflow->stats.protocol_flows[i];
        }

        cumulative_stats.ndpi_flow_count += ndpi_thread_info[thread_id].workflow->stats.ndpi_flow_count;
        cumulative_stats.flow_count[0] += ndpi_thread_info[thread_id].workflow->stats.flow_count[0];
        cumulative_stats.flow_count[1] += ndpi_thread_info[thread_id].workflow->stats.flow_count[1];
        cumulative_stats.flow_count[2] += ndpi_thread_info[thread_id].workflow->stats.flow_count[2];
        cumulative_stats.tcp_count += ndpi_thread_info[thread_id].workflow->stats.tcp_count;
        cumulative_stats.udp_count += ndpi_thread_info[thread_id].workflow->stats.udp_count;
        cumulative_stats.mpls_count += ndpi_thread_info[thread_id].workflow->stats.mpls_count;
        cumulative_stats.pppoe_count += ndpi_thread_info[thread_id].workflow->stats.pppoe_count;
        cumulative_stats.vlan_count += ndpi_thread_info[thread_id].workflow->stats.vlan_count;
        cumulative_stats.fragmented_count += ndpi_thread_info[thread_id].workflow->stats.fragmented_count;
        for (i = 0; i < sizeof(cumulative_stats.packet_len) / sizeof(cumulative_stats.packet_len[0]); i++)
            cumulative_stats.packet_len[i] += ndpi_thread_info[thread_id].workflow->stats.packet_len[i];
        cumulative_stats.max_packet_len += ndpi_thread_info[thread_id].workflow->stats.max_packet_len;

        cumulative_stats.dpi_packet_count[0] += ndpi_thread_info[thread_id].workflow->stats.dpi_packet_count[0];
        cumulative_stats.dpi_packet_count[1] += ndpi_thread_info[thread_id].workflow->stats.dpi_packet_count[1];
        cumulative_stats.dpi_packet_count[2] += ndpi_thread_info[thread_id].workflow->stats.dpi_packet_count[2];

        for (i = 0; i < sizeof(cumulative_stats.flow_confidence) / sizeof(cumulative_stats.flow_confidence[0]); i++)
            cumulative_stats.flow_confidence[i] += ndpi_thread_info[thread_id].workflow->stats.flow_confidence[i];

        cumulative_stats.num_dissector_calls += ndpi_thread_info[thread_id].workflow->stats.num_dissector_calls;

        /* LRU caches */
        for (i = 0; i < NDPI_LRUCACHE_MAX; i++) {
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
                    cumulative_stats.lru_stats[i].n_insert += s.n_insert;
                    cumulative_stats.lru_stats[i].n_search += s.n_search;
                    cumulative_stats.lru_stats[i].n_found += s.n_found;
                }
            }
        }

        /* Automas */
        for (i = 0; i < NDPI_AUTOMA_MAX; i++) {
            struct ndpi_automa_stats s;
            ndpi_get_automa_stats(ndpi_thread_info[thread_id].workflow->ndpi_struct, i, &s);
            cumulative_stats.automa_stats[i].n_search += s.n_search;
            cumulative_stats.automa_stats[i].n_found += s.n_found;
        }

        /* Patricia trees */
        for (i = 0; i < NDPI_PTREE_MAX; i++) {
            struct ndpi_patricia_tree_stats s;
            ndpi_get_patricia_stats(ndpi_thread_info[thread_id].workflow->ndpi_struct, i, &s);
            cumulative_stats.patricia_stats[i].n_search += s.n_search;
            cumulative_stats.patricia_stats[i].n_found += s.n_found;
        }
    }

    if (cumulative_stats.total_wire_bytes == 0)
        goto free_stats;

    if (!quiet_mode) {
        printw("\nnDPI Memory statistics:\n");
        printw("\tnDPI Memory (once):      %-13s\n", formatBytes(ndpi_get_ndpi_detection_module_size(), buf, sizeof(buf)));
        printw("\tFlow Memory (per flow):  %-13s\n", formatBytes(ndpi_detection_get_sizeof_ndpi_flow_struct(), buf, sizeof(buf)));
        printw("\tActual Memory:           %-13s\n", formatBytes(current_ndpi_memory, buf, sizeof(buf)));
        printw("\tPeak Memory:             %-13s\n", formatBytes(max_ndpi_memory, buf, sizeof(buf)));
        printw("\tSetup Time:              %lu msec\n", (unsigned long)(setup_time_usec / 1000));
        printw("\tPacket Processing Time:  %lu msec\n", (unsigned long)(processing_time_usec / 1000));

        printw("\nTraffic statistics:\n");
        printw("\tEthernet bytes:        %-13llu (includes ethernet CRC/IFC/trailer)\n",
            (long long unsigned int)cumulative_stats.total_wire_bytes);
        printw("\tDiscarded bytes:       %-13llu\n",
            (long long unsigned int)cumulative_stats.total_discarded_bytes);
        printw("\tIP packets:            %-13llu of %llu packets total\n",
            (long long unsigned int)cumulative_stats.ip_packet_count,
            (long long unsigned int)cumulative_stats.raw_packet_count);
     /* In order to prevent Floating point exception in case of no traffic*/
        if (cumulative_stats.total_ip_bytes && cumulative_stats.raw_packet_count)
        {
            avg_pkt_size = (unsigned int)(cumulative_stats.total_ip_bytes / cumulative_stats.raw_packet_count);
        }
        printw("\tIP bytes:              %-13llu (avg pkt size %u bytes)\n",
            (long long unsigned int)cumulative_stats.total_ip_bytes, avg_pkt_size);
        printw("\tUnique flows:          %-13u\n", cumulative_stats.ndpi_flow_count);
        printw("\tTCP Packets:           %-13lu\n", (unsigned long)cumulative_stats.tcp_count);
        printw("\tUDP Packets:           %-13lu\n", (unsigned long)cumulative_stats.udp_count);
        printw("\tVLAN Packets:          %-13lu\n", (unsigned long)cumulative_stats.vlan_count);
        printw("\tMPLS Packets:          %-13lu\n", (unsigned long)cumulative_stats.mpls_count);
        printw("\tPPPoE Packets:         %-13lu\n", (unsigned long)cumulative_stats.pppoe_count);
        printw("\tFragmented Packets:    %-13lu\n", (unsigned long)cumulative_stats.fragmented_count);
        printw("\tMax Packet size:       %-13u\n", cumulative_stats.max_packet_len);
        printw("\tPacket Len < 64:       %-13lu\n", (unsigned long)cumulative_stats.packet_len[0]);
        printw("\tPacket Len 64-128:     %-13lu\n", (unsigned long)cumulative_stats.packet_len[1]);
        printw("\tPacket Len 128-256:    %-13lu\n", (unsigned long)cumulative_stats.packet_len[2]);
        printw("\tPacket Len 256-1024:   %-13lu\n", (unsigned long)cumulative_stats.packet_len[3]);
        printw("\tPacket Len 1024-1500:  %-13lu\n", (unsigned long)cumulative_stats.packet_len[4]);
        printw("\tPacket Len > 1500:     %-13lu\n", (unsigned long)cumulative_stats.packet_len[5]);

        if (processing_time_usec > 0) {
            char buf[32], buf1[32], when[64];
            float t = (float)(cumulative_stats.ip_packet_count * 1000000) / (float)processing_time_usec;
            float b = (float)(cumulative_stats.total_wire_bytes * 8 * 1000000) / (float)processing_time_usec;
            float traffic_duration;
            struct tm result;

            if (live_capture) traffic_duration = processing_time_usec;
            else traffic_duration = ((u_int64_t)pcap_end.tv_sec * 1000000 + pcap_end.tv_usec) - ((u_int64_t)pcap_start.tv_sec * 1000000 + pcap_start.tv_usec);

            printw("\tnDPI throughput:       %s pps / %s/sec\n", formatPackets(t, buf), formatTraffic(b, 1, buf1));
            if (traffic_duration != 0) {
                t = (float)(cumulative_stats.ip_packet_count * 1000000) / (float)traffic_duration;
                b = (float)(cumulative_stats.total_wire_bytes * 8 * 1000000) / (float)traffic_duration;
            }
            else {
                t = 0;
                b = 0;
            }
#ifdef WIN32
      /* localtime() on Windows is thread-safe */
            time_t tv_sec = pcap_start.tv_sec;
            struct tm* tm_ptr = localtime(&tv_sec);
            result = *tm_ptr;
#else
            localtime_r(&pcap_start.tv_sec, &result);
#endif
            strftime(when, sizeof(when), "%d/%b/%Y %H:%M:%S", &result);
            printw("\tAnalysis begin:        %s\n", when);
#ifdef WIN32
      /* localtime() on Windows is thread-safe */
            tv_sec = pcap_end.tv_sec;
            tm_ptr = localtime(&tv_sec);
            result = *tm_ptr;
#else
            localtime_r(&pcap_end.tv_sec, &result);
#endif
            strftime(when, sizeof(when), "%d/%b/%Y %H:%M:%S", &result);
            printw("\tAnalysis end:          %s\n", when);
            printw("\tTraffic throughput:    %s pps / %s/sec\n", formatPackets(t, buf), formatTraffic(b, 1, buf1));
            printw("\tTraffic duration:      %.3f sec\n", traffic_duration / 1000000);
        }

        if (cumulative_stats.guessed_flow_protocols)
            printw("\tGuessed flow protos:   %-13u\n", cumulative_stats.guessed_flow_protocols);

        if (cumulative_stats.flow_count[0])
            printw("\tDPI Packets (TCP):     %-13llu (%.2f pkts/flow)\n",
                (long long unsigned int)cumulative_stats.dpi_packet_count[0],
                cumulative_stats.dpi_packet_count[0] / (float)cumulative_stats.flow_count[0]);
        if (cumulative_stats.flow_count[1])
            printw("\tDPI Packets (UDP):     %-13llu (%.2f pkts/flow)\n",
                (long long unsigned int)cumulative_stats.dpi_packet_count[1],
                cumulative_stats.dpi_packet_count[1] / (float)cumulative_stats.flow_count[1]);
        if (cumulative_stats.flow_count[2])
            printw("\tDPI Packets (other):   %-13llu (%.2f pkts/flow)\n",
                (long long unsigned int)cumulative_stats.dpi_packet_count[2],
                cumulative_stats.dpi_packet_count[2] / (float)cumulative_stats.flow_count[2]);

        for (i = 0; i < sizeof(cumulative_stats.flow_confidence) / sizeof(cumulative_stats.flow_confidence[0]); i++) {
            if (cumulative_stats.flow_confidence[i] != 0)
                printw("\tConfidence: %-10s %-13llu (flows)\n", ndpi_confidence_get_name(i),
                    (long long unsigned int)cumulative_stats.flow_confidence[i]);
        }

        if (dump_internal_stats) {
            char buf[1024];

            if (cumulative_stats.ndpi_flow_count)
                printw("\tNum dissector calls:   %-13llu (%.2f diss/flow)\n",
                    (long long unsigned int)cumulative_stats.num_dissector_calls,
                    cumulative_stats.num_dissector_calls / (float)cumulative_stats.ndpi_flow_count);

            printw("\tLRU cache ookla:      %llu/%llu/%llu (insert/search/found)\n",
                (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_OOKLA].n_insert,
                (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_OOKLA].n_search,
                (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_OOKLA].n_found);
            printw("\tLRU cache bittorrent: %llu/%llu/%llu (insert/search/found)\n",
                (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_BITTORRENT].n_insert,
                (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_BITTORRENT].n_search,
                (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_BITTORRENT].n_found);
            printw("\tLRU cache stun:       %llu/%llu/%llu (insert/search/found)\n",
                (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_STUN].n_insert,
                (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_STUN].n_search,
                (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_STUN].n_found);
            printw("\tLRU cache tls_cert:   %llu/%llu/%llu (insert/search/found)\n",
                (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_TLS_CERT].n_insert,
                (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_TLS_CERT].n_search,
                (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_TLS_CERT].n_found);
            printw("\tLRU cache mining:     %llu/%llu/%llu (insert/search/found)\n",
                (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MINING].n_insert,
                (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MINING].n_search,
                (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MINING].n_found);
            printw("\tLRU cache msteams:    %llu/%llu/%llu (insert/search/found)\n",
                (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MSTEAMS].n_insert,
                (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MSTEAMS].n_search,
                (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MSTEAMS].n_found);
            printw("\tLRU cache fpc_dns:    %llu/%llu/%llu (insert/search/found)\n",
                (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_FPC_DNS].n_insert,
                (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_FPC_DNS].n_search,
                (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_FPC_DNS].n_found);

            printw("\tAutoma host:          %llu/%llu (search/found)\n",
                (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_HOST].n_search,
                (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_HOST].n_found);
            printw("\tAutoma domain:        %llu/%llu (search/found)\n",
                (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_DOMAIN].n_search,
                (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_DOMAIN].n_found);
            printw("\tAutoma tls cert:      %llu/%llu (search/found)\n",
                (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_TLS_CERT].n_search,
                (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_TLS_CERT].n_found);
            printw("\tAutoma risk mask:     %llu/%llu (search/found)\n",
                (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_RISK_MASK].n_search,
                (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_RISK_MASK].n_found);
            printw("\tAutoma common alpns:  %llu/%llu (search/found)\n",
                (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_COMMON_ALPNS].n_search,
                (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_COMMON_ALPNS].n_found);

            printw("\tPatricia risk mask:   %llu/%llu (search/found)\n",
                (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK].n_search,
                (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK].n_found);
            printw("\tPatricia risk mask IPv6: %llu/%llu (search/found)\n",
                (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK6].n_search,
                (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK6].n_found);
            printw("\tPatricia risk:        %llu/%llu (search/found)\n",
                (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK].n_search,
                (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK].n_found);
            printw("\tPatricia risk IPv6:   %llu/%llu (search/found)\n",
                (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK6].n_search,
                (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK6].n_found);
            printw("\tPatricia protocols:   %llu/%llu (search/found)\n",
                (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS].n_search,
                (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS].n_found);
            printw("\tPatricia protocols IPv6: %llu/%llu (search/found)\n",
                (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS6].n_search,
                (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS6].n_found);

            if (enable_malloc_bins)
                printw("\tData-path malloc histogram: %s\n", ndpi_print_bin(&malloc_bins, 0, buf, sizeof(buf)));
        }
    }

    if (!quiet_mode) printw("\n\nDetected protocols:\n");
    for (i = 0; i <= ndpi_get_num_supported_protocols(ndpi_thread_info[0].workflow->ndpi_struct); i++) {
        ndpi_protocol_breed_t breed = ndpi_get_proto_breed(ndpi_thread_info[0].workflow->ndpi_struct,
            ndpi_map_ndpi_id_to_user_proto_id(ndpi_thread_info[0].workflow->ndpi_struct, i));

        if (cumulative_stats.protocol_counter[i] > 0) {
            breed_stats_bytes[breed] += (long long unsigned int)cumulative_stats.protocol_counter_bytes[i];
            breed_stats_pkts[breed] += (long long unsigned int)cumulative_stats.protocol_counter[i];
            breed_stats_flows[breed] += (long long unsigned int)cumulative_stats.protocol_flows[i];

            if (!quiet_mode) {
                printw("\t%-20s packets: %-13llu bytes: %-13llu "
                    "flows: %-13u\n",
                    ndpi_get_proto_name(ndpi_thread_info[0].workflow->ndpi_struct,
                        ndpi_map_ndpi_id_to_user_proto_id(ndpi_thread_info[0].workflow->ndpi_struct, i)),
                    (long long unsigned int)cumulative_stats.protocol_counter[i],
                    (long long unsigned int)cumulative_stats.protocol_counter_bytes[i],
                    cumulative_stats.protocol_flows[i]);
            }
        }
    }

    if (!quiet_mode) {
        printw("\n\nProtocol statistics:\n");

        for (i = 0; i < NUM_BREEDS; i++) {
            if (breed_stats_pkts[i] > 0) {
                printw("\t%-20s packets: %-13llu bytes: %-13llu "
                    "flows: %-13llu\n",
                    ndpi_get_proto_breed_name(i),
                    breed_stats_pkts[i], breed_stats_bytes[i], breed_stats_flows[i]);
            }
        }
    }

    ncurses_printRiskStats();

    if (stats_flag || verbose == 3) {
        HASH_SORT(srcStats, port_stats_sort);
        HASH_SORT(dstStats, port_stats_sort);
    }

    if (verbose == 3) {
        printw("\n\nSource Ports Stats:\n");
        port_stats_print(srcStats);

        printw("\nDestination Ports Stats:\n");
        port_stats_print(dstStats);
    }

free_stats:
    if (scannerHosts) {
        deleteScanners(scannerHosts);
        scannerHosts = NULL;
    }

    if (receivers) {
        receivers_delete(receivers);
        receivers = NULL;
    }

    if (topReceivers) {
        receivers_delete(topReceivers);
        topReceivers = NULL;
    }

    if (srcStats) {
        port_stats_delete(srcStats);
        srcStats = NULL;
    }

    if (dstStats) {
        port_stats_delete(dstStats);
        dstStats = NULL;
    }
}

void ncurses_printRiskStats() {
    if (!quiet_mode) {
        u_int thread_id, i;

        for (thread_id = 0; thread_id < num_threads; thread_id++) {
            for (i = 0; i < NUM_ROOTS; i++)
                ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
                    node_flow_risk_walker, &thread_id);
        }

        if (risks_found) {
            printw("\nRisk stats [found %u (%.1f %%) flows with risks]:\n",
                flows_with_risks,
                (100. * flows_with_risks) / (float)cumulative_stats.ndpi_flow_count);

            for (i = 0; i < NDPI_MAX_RISK; i++) {
                ndpi_risk_enum r = (ndpi_risk_enum)i;

                if (risk_stats[r] != 0)
                    printw("\t%-40s %5u [%4.01f %%]\n", ndpi_risk2str(r), risk_stats[r],
                        (float)(risk_stats[r] * 100) / (float)risks_found);
            }

            printw("\n\tNOTE: as one flow can have multiple risks set, the sum of the\n"
                "\t      last column can exceed the number of flows with risks.\n");
            printw("\n\n");
        }
    }
}

