
#include "../../include/lib-print-ncurses.h"

// Print result to an ncurses window
void* ncurses_print_result(uint64_t processing_time_usec) {
    u_int32_t i;
    char buf[32];

    if (global_data.traffic.total_wire_bytes == 0)
        goto free_stats;

    if (!quiet_mode) {
        printw("\nnDPI Memory statistics:\n");
        printw("\tnDPI Memory (once):      %-13s\n", formatBytes(global_data.memory.mem_once, buf, sizeof(buf)));
        printw("\tFlow Memory (per flow):  %-13s\n", formatBytes(global_data.memory.mem_per_flow, buf, sizeof(buf)));
        printw("\tActual Memory:           %-13s\n", formatBytes(global_data.memory.mem_actual, buf, sizeof(buf)));
        printw("\tPeak Memory:             %-13s\n", formatBytes(global_data.memory.mem_peak, buf, sizeof(buf)));
        printw("\tSetup Time:              %lu msec\n", global_data.time.processing_time);
        printw("\tPacket Processing Time:  %lu msec\n", global_data.time.setup_time);

        printw("\nTraffic statistics:\n");
        printw("\tEthernet bytes:        %-13llu (includes ethernet CRC/IFC/trailer)\n",
            (long long unsigned int)global_data.traffic.total_wire_bytes);
        printw("\tDiscarded bytes:       %-13llu\n",
            (long long unsigned int)global_data.traffic.total_discarded_bytes);
        printw("\tIP packets:            %-13llu of %llu packets total\n",
            (long long unsigned int)global_data.traffic.ip_packet_count,
            (long long unsigned int)global_data.traffic.raw_packet_count);
        printw("\tIP bytes:              %-13llu (avg pkt size %u bytes)\n",
            (long long unsigned int)global_data.traffic.total_ip_bytes,
            global_data.traffic.avg_pkt_size);
        printw("\tUnique flows:          %-13u\n", global_data.traffic.ndpi_flow_count);
        printw("\tTCP Packets:           %-13lu\n", global_data.traffic.tcp_count);
        printw("\tUDP Packets:           %-13lu\n", global_data.traffic.udp_count);
        printw("\tVLAN Packets:          %-13lu\n", global_data.traffic.vlan_count);
        printw("\tMPLS Packets:          %-13lu\n", global_data.traffic.mpls_count);
        printw("\tPPPoE Packets:         %-13lu\n", global_data.traffic.pppoe_count);
        printw("\tFragmented Packets:    %-13lu\n", global_data.traffic.fragmented_count);
        printw("\tMax Packet size:       %-13u\n", global_data.traffic.max_packet_len);
        printw("\tPacket Len < 64:       %-13lu\n", global_data.traffic.packet_len[0]);
        printw("\tPacket Len 64-128:     %-13lu\n", global_data.traffic.packet_len[1]);
        printw("\tPacket Len 128-256:    %-13lu\n", global_data.traffic.packet_len[2]);
        printw("\tPacket Len 256-1024:   %-13lu\n", global_data.traffic.packet_len[3]);
        printw("\tPacket Len 1024-1500:  %-13lu\n", global_data.traffic.packet_len[4]);
        printw("\tPacket Len > 1500:     %-13lu\n", global_data.traffic.packet_len[5]);

        if (processing_time_usec > 0) {
            char buf[32], buf1[32], when[64];
            struct tm result;

            printw("\tnDPI throughput:       %s pps / %s/sec\n",
                formatPackets(global_data.traffic.ndpi_packets_per_second, buf),
                formatTraffic(global_data.traffic.ndpi_bytes_per_second, 1, buf1)
            );

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
            printw("\tTraffic throughput:    %s pps / %s/sec\n",
                formatPackets(global_data.traffic.traffic_packets_per_second, buf),
                formatTraffic(global_data.traffic.traffic_bytes_per_second, 1, buf1)
            );
            printw("\tTraffic duration:      %.3f sec\n", global_data.traffic.traffic_duration / 1000000);
        }

        if (global_data.traffic.guessed_flow_protocols) {
            printw("\tGuessed flow protos:   %-13u\n", global_data.traffic.guessed_flow_protocols);
        }

        if (global_data.traffic.dpi_flow_count[FLOW_TCP]) {
            printw("\tDPI Packets (TCP):     %-13llu (%.2f pkts/flow)\n",
                (long long unsigned int)global_data.traffic.dpi_packet_count[FLOW_TCP],
                global_data.traffic.dpi_packet_count[FLOW_TCP] / (float)global_data.traffic.dpi_flow_count[FLOW_TCP]);
        }
        if (global_data.traffic.dpi_flow_count[FLOW_UDP]) {
            printw("\tDPI Packets (UDP):     %-13llu (%.2f pkts/flow)\n",
                (long long unsigned int)global_data.traffic.dpi_packet_count[FLOW_UDP],
                global_data.traffic.dpi_packet_count[FLOW_UDP] / (float)global_data.traffic.dpi_flow_count[FLOW_UDP]);
        }
        if (global_data.traffic.dpi_flow_count[FLOW_OTHER]) {
            printw("\tDPI Packets (other):   %-13llu (%.2f pkts/flow)\n",
                (long long unsigned int)global_data.traffic.dpi_packet_count[FLOW_OTHER],
                global_data.traffic.dpi_packet_count[FLOW_OTHER] / (float)global_data.traffic.dpi_flow_count[FLOW_OTHER]);
        }

        for (i = 0; i < NDPI_CONFIDENCE_MAX; i++) {
            if (global_data.traffic.flow_confidence[i] != 0) {
                printw("\tConfidence: %-10s %-13llu (flows)\n", ndpi_confidence_get_name(i),
                    (long long unsigned int)global_data.traffic.flow_confidence[i]);
            }
        }

        if (dump_internal_stats) {
            char buf[1024];

            if (global_data.traffic.ndpi_flow_count)
                printw("\tNum dissector calls:   %-13llu (%.2f diss/flow)\n",
                    (long long unsigned int)global_data.traffic.num_dissector_calls,
                    global_data.traffic.num_dissector_calls / (float)global_data.traffic.ndpi_flow_count);

            printw("\tLRU cache ookla:      %llu/%llu/%llu (insert/search/found)\n",
                (long long unsigned int)global_data.detail.lru_stats[NDPI_LRUCACHE_OOKLA].n_insert,
                (long long unsigned int)global_data.detail.lru_stats[NDPI_LRUCACHE_OOKLA].n_search,
                (long long unsigned int)global_data.detail.lru_stats[NDPI_LRUCACHE_OOKLA].n_found);
            printw("\tLRU cache bittorrent: %llu/%llu/%llu (insert/search/found)\n",
                (long long unsigned int)global_data.detail.lru_stats[NDPI_LRUCACHE_BITTORRENT].n_insert,
                (long long unsigned int)global_data.detail.lru_stats[NDPI_LRUCACHE_BITTORRENT].n_search,
                (long long unsigned int)global_data.detail.lru_stats[NDPI_LRUCACHE_BITTORRENT].n_found);
            printw("\tLRU cache stun:       %llu/%llu/%llu (insert/search/found)\n",
                (long long unsigned int)global_data.detail.lru_stats[NDPI_LRUCACHE_STUN].n_insert,
                (long long unsigned int)global_data.detail.lru_stats[NDPI_LRUCACHE_STUN].n_search,
                (long long unsigned int)global_data.detail.lru_stats[NDPI_LRUCACHE_STUN].n_found);
            printw("\tLRU cache tls_cert:   %llu/%llu/%llu (insert/search/found)\n",
                (long long unsigned int)global_data.detail.lru_stats[NDPI_LRUCACHE_TLS_CERT].n_insert,
                (long long unsigned int)global_data.detail.lru_stats[NDPI_LRUCACHE_TLS_CERT].n_search,
                (long long unsigned int)global_data.detail.lru_stats[NDPI_LRUCACHE_TLS_CERT].n_found);
            printw("\tLRU cache mining:     %llu/%llu/%llu (insert/search/found)\n",
                (long long unsigned int)global_data.detail.lru_stats[NDPI_LRUCACHE_MINING].n_insert,
                (long long unsigned int)global_data.detail.lru_stats[NDPI_LRUCACHE_MINING].n_search,
                (long long unsigned int)global_data.detail.lru_stats[NDPI_LRUCACHE_MINING].n_found);
            printw("\tLRU cache msteams:    %llu/%llu/%llu (insert/search/found)\n",
                (long long unsigned int)global_data.detail.lru_stats[NDPI_LRUCACHE_MSTEAMS].n_insert,
                (long long unsigned int)global_data.detail.lru_stats[NDPI_LRUCACHE_MSTEAMS].n_search,
                (long long unsigned int)global_data.detail.lru_stats[NDPI_LRUCACHE_MSTEAMS].n_found);
            printw("\tLRU cache fpc_dns:    %llu/%llu/%llu (insert/search/found)\n",
                (long long unsigned int)global_data.detail.lru_stats[NDPI_LRUCACHE_FPC_DNS].n_insert,
                (long long unsigned int)global_data.detail.lru_stats[NDPI_LRUCACHE_FPC_DNS].n_search,
                (long long unsigned int)global_data.detail.lru_stats[NDPI_LRUCACHE_FPC_DNS].n_found);

            printw("\tAutoma host:          %llu/%llu (search/found)\n",
                (long long unsigned int)global_data.detail.automa_stats[NDPI_AUTOMA_HOST].n_search,
                (long long unsigned int)global_data.detail.automa_stats[NDPI_AUTOMA_HOST].n_found);
            printw("\tAutoma domain:        %llu/%llu (search/found)\n",
                (long long unsigned int)global_data.detail.automa_stats[NDPI_AUTOMA_DOMAIN].n_search,
                (long long unsigned int)global_data.detail.automa_stats[NDPI_AUTOMA_DOMAIN].n_found);
            printw("\tAutoma tls cert:      %llu/%llu (search/found)\n",
                (long long unsigned int)global_data.detail.automa_stats[NDPI_AUTOMA_TLS_CERT].n_search,
                (long long unsigned int)global_data.detail.automa_stats[NDPI_AUTOMA_TLS_CERT].n_found);
            printw("\tAutoma risk mask:     %llu/%llu (search/found)\n",
                (long long unsigned int)global_data.detail.automa_stats[NDPI_AUTOMA_RISK_MASK].n_search,
                (long long unsigned int)global_data.detail.automa_stats[NDPI_AUTOMA_RISK_MASK].n_found);
            printw("\tAutoma common alpns:  %llu/%llu (search/found)\n",
                (long long unsigned int)global_data.detail.automa_stats[NDPI_AUTOMA_COMMON_ALPNS].n_search,
                (long long unsigned int)global_data.detail.automa_stats[NDPI_AUTOMA_COMMON_ALPNS].n_found);

            printw("\tPatricia risk mask:   %llu/%llu (search/found)\n",
                (long long unsigned int)global_data.detail.patricia_stats[NDPI_PTREE_RISK_MASK].n_search,
                (long long unsigned int)global_data.detail.patricia_stats[NDPI_PTREE_RISK_MASK].n_found);
            printw("\tPatricia risk mask IPv6: %llu/%llu (search/found)\n",
                (long long unsigned int)global_data.detail.patricia_stats[NDPI_PTREE_RISK_MASK6].n_search,
                (long long unsigned int)global_data.detail.patricia_stats[NDPI_PTREE_RISK_MASK6].n_found);
            printw("\tPatricia risk:        %llu/%llu (search/found)\n",
                (long long unsigned int)global_data.detail.patricia_stats[NDPI_PTREE_RISK].n_search,
                (long long unsigned int)global_data.detail.patricia_stats[NDPI_PTREE_RISK].n_found);
            printw("\tPatricia risk IPv6:   %llu/%llu (search/found)\n",
                (long long unsigned int)global_data.detail.patricia_stats[NDPI_PTREE_RISK6].n_search,
                (long long unsigned int)global_data.detail.patricia_stats[NDPI_PTREE_RISK6].n_found);
            printw("\tPatricia protocols:   %llu/%llu (search/found)\n",
                (long long unsigned int)global_data.detail.patricia_stats[NDPI_PTREE_PROTOCOLS].n_search,
                (long long unsigned int)global_data.detail.patricia_stats[NDPI_PTREE_PROTOCOLS].n_found);
            printw("\tPatricia protocols IPv6: %llu/%llu (search/found)\n",
                (long long unsigned int)global_data.detail.patricia_stats[NDPI_PTREE_PROTOCOLS6].n_search,
                (long long unsigned int)global_data.detail.patricia_stats[NDPI_PTREE_PROTOCOLS6].n_found);

            if (enable_malloc_bins)
                printw("\tData-path malloc histogram: %s\n", ndpi_print_bin(&malloc_bins, 0, buf, sizeof(buf)));
        }
    }

    printw("\n\nDetected protocols:\n");
    struct data_protocol* protocol_array = global_data.protocol.content;
    for (size_t i = 0; i < global_data.protocol.length; i++) {
        printw("\t%-20s packets: %-13llu bytes: %-13llu "
            "flows: %-13llu\n",
            protocol_array[i].name.content,
            (long long unsigned int)protocol_array[i].packet_count,
            (long long unsigned int)protocol_array[i].byte_count,
            (long long unsigned int)protocol_array[i].flow_count
        );
    }

    printw("\n\nProtocol statistics:\n");
    struct data_classification* classification_array = global_data.classification.content;
    for (size_t i = 0; i < global_data.classification.length; i++) {
        printw("\t%-20s packets: %-13llu bytes: %-13llu "
            "flows: %-13llu\n",
            classification_array[i].name.content,
            (long long unsigned int)classification_array[i].packet_count,
            (long long unsigned int)classification_array[i].byte_count,
            (long long unsigned int)classification_array[i].flow_count
        );
    }

    ncurses_print_risk_stats();
    ncurses_print_flows_stats();

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

    return NULL;
}

void ncurses_print_risk_stats() {
    if (!quiet_mode) {
        if (global_data.risk.length > 0) {
            printw("\nRisk stats [found %u (%.1f %%) flows with risks]:\n",
                global_data.risk_total_count,
                (100. * global_data.risk_total_count) / (float)global_data.traffic.ndpi_flow_count);

            struct data_risk* risk_array = global_data.risk.content;
            for (size_t i = 0; i < global_data.risk.length; i++) {
                printw("\t%-40s %5u [%4.01f %%]\n",
                    risk_array[i].name.content,
                    risk_array[i].flow_count,
                    risk_array[i].ratio
                );
            }

            printw("\n\tNOTE: as one flow can have multiple risks set, the sum of the\n"
                "\t      last column can exceed the number of flows with risks.\n");
            printw("\n\n");
        }
    }
}

void ncurses_print_flows_stats() {
    FILE* out = results_file ? results_file : stdout;
    struct flow_info* known_flow_array = global_data.known_flow.content;
    uint32_t known_flow_count = global_data.known_flow.length;
    struct flow_info* unknown_flow_array = global_data.unknown_flow.content;
    uint32_t unknown_flow_count = global_data.unknown_flow.length;

    if (enable_payload_analyzer) {
        ndpi_report_payload_stats(out);
    }

    if (verbose) {
        ndpi_host_ja3_fingerprints* ja3ByHostsHashT = NULL; // outer hash table
        ndpi_ja3_fingerprints_host* hostByJA3C_ht = NULL;   // for client
        ndpi_ja3_fingerprints_host* hostByJA3S_ht = NULL;   // for server
        unsigned int i;
        ndpi_host_ja3_fingerprints* ja3ByHost_element = NULL;
        ndpi_ja3_info* info_of_element = NULL;
        ndpi_host_ja3_fingerprints* tmp = NULL;
        ndpi_ja3_info* tmp2 = NULL;
        unsigned int num_ja3_ja4_client;
        unsigned int num_ja3_server;

        printw("\n");

        if ((verbose == 2) || (verbose == 3)) {
            for (i = 0; i < known_flow_count; i++) {
                ndpi_host_ja3_fingerprints* ja3ByHostFound = NULL;
                ndpi_ja3_fingerprints_host* hostByJA3Found = NULL;

                //check if this is a ssh-ssl flow
                if (known_flow_array[i].flow->ssh_tls.ja3_client[0] != '\0') {
                  //looking if the host is already in the hash table
                    HASH_FIND_INT(ja3ByHostsHashT, &(known_flow_array[i].flow->src_ip), ja3ByHostFound);

                    //host ip -> ja3
                    if (ja3ByHostFound == NULL) {
                      //adding the new host
                        ndpi_host_ja3_fingerprints* newHost = ndpi_malloc(sizeof(ndpi_host_ja3_fingerprints));
                        newHost->host_client_info_hasht = NULL;
                        newHost->host_server_info_hasht = NULL;
                        newHost->ip_string = known_flow_array[i].flow->src_name;
                        newHost->ip = known_flow_array[i].flow->src_ip;
                        newHost->dns_name = known_flow_array[i].flow->host_server_name;

                        ndpi_ja3_info* newJA3 = ndpi_malloc(sizeof(ndpi_ja3_info));
                        newJA3->ja3 = known_flow_array[i].flow->ssh_tls.ja3_client;
                        newJA3->unsafe_cipher = known_flow_array[i].flow->ssh_tls.client_unsafe_cipher;
                        //adding the new ja3 fingerprint
                        HASH_ADD_KEYPTR(hh, newHost->host_client_info_hasht,
                            newJA3->ja3, strlen(newJA3->ja3), newJA3);
            //adding the new host
                        HASH_ADD_INT(ja3ByHostsHashT, ip, newHost);
                    }
                    else {
                   //host already in the hash table
                        ndpi_ja3_info* infoFound = NULL;

                        HASH_FIND_STR(ja3ByHostFound->host_client_info_hasht,
                            known_flow_array[i].flow->ssh_tls.ja3_client, infoFound);

                        if (infoFound == NULL) {
                            ndpi_ja3_info* newJA3 = ndpi_malloc(sizeof(ndpi_ja3_info));
                            newJA3->ja3 = known_flow_array[i].flow->ssh_tls.ja3_client;
                            newJA3->unsafe_cipher = known_flow_array[i].flow->ssh_tls.client_unsafe_cipher;
                            HASH_ADD_KEYPTR(hh, ja3ByHostFound->host_client_info_hasht,
                                newJA3->ja3, strlen(newJA3->ja3), newJA3);
                        }
                    }

                    //ja3 -> host ip
                    HASH_FIND_STR(hostByJA3C_ht, known_flow_array[i].flow->ssh_tls.ja3_client, hostByJA3Found);
                    if (hostByJA3Found == NULL) {
                        ndpi_ip_dns* newHost = ndpi_malloc(sizeof(ndpi_ip_dns));

                        newHost->ip = known_flow_array[i].flow->src_ip;
                        newHost->ip_string = known_flow_array[i].flow->src_name;
                        newHost->dns_name = known_flow_array[i].flow->host_server_name;

                        ndpi_ja3_fingerprints_host* newElement = ndpi_malloc(sizeof(ndpi_ja3_fingerprints_host));
                        newElement->ja3 = known_flow_array[i].flow->ssh_tls.ja3_client;
                        newElement->unsafe_cipher = known_flow_array[i].flow->ssh_tls.client_unsafe_cipher;
                        newElement->ipToDNS_ht = NULL;

                        HASH_ADD_INT(newElement->ipToDNS_ht, ip, newHost);
                        HASH_ADD_KEYPTR(hh, hostByJA3C_ht, newElement->ja3, strlen(newElement->ja3),
                            newElement);
                    }
                    else {
                        ndpi_ip_dns* innerElement = NULL;
                        HASH_FIND_INT(hostByJA3Found->ipToDNS_ht, &(known_flow_array[i].flow->src_ip), innerElement);
                        if (innerElement == NULL) {
                            ndpi_ip_dns* newInnerElement = ndpi_malloc(sizeof(ndpi_ip_dns));
                            newInnerElement->ip = known_flow_array[i].flow->src_ip;
                            newInnerElement->ip_string = known_flow_array[i].flow->src_name;
                            newInnerElement->dns_name = known_flow_array[i].flow->host_server_name;
                            HASH_ADD_INT(hostByJA3Found->ipToDNS_ht, ip, newInnerElement);
                        }
                    }
                }

                if (known_flow_array[i].flow->ssh_tls.ja3_server[0] != '\0') {
                  //looking if the host is already in the hash table
                    HASH_FIND_INT(ja3ByHostsHashT, &(known_flow_array[i].flow->dst_ip), ja3ByHostFound);
                    if (ja3ByHostFound == NULL) {
                      //adding the new host in the hash table
                        ndpi_host_ja3_fingerprints* newHost = ndpi_malloc(sizeof(ndpi_host_ja3_fingerprints));
                        newHost->host_client_info_hasht = NULL;
                        newHost->host_server_info_hasht = NULL;
                        newHost->ip_string = known_flow_array[i].flow->dst_name;
                        newHost->ip = known_flow_array[i].flow->dst_ip;
                        newHost->dns_name = known_flow_array[i].flow->ssh_tls.server_info;

                        ndpi_ja3_info* newJA3 = ndpi_malloc(sizeof(ndpi_ja3_info));
                        newJA3->ja3 = known_flow_array[i].flow->ssh_tls.ja3_server;
                        newJA3->unsafe_cipher = known_flow_array[i].flow->ssh_tls.server_unsafe_cipher;
                        //adding the new ja3 fingerprint
                        HASH_ADD_KEYPTR(hh, newHost->host_server_info_hasht, newJA3->ja3,
                            strlen(newJA3->ja3), newJA3);
            //adding the new host
                        HASH_ADD_INT(ja3ByHostsHashT, ip, newHost);
                    }
                    else {
                   //host already in the hashtable
                        ndpi_ja3_info* infoFound = NULL;
                        HASH_FIND_STR(ja3ByHostFound->host_server_info_hasht,
                            known_flow_array[i].flow->ssh_tls.ja3_server, infoFound);
                        if (infoFound == NULL) {
                            ndpi_ja3_info* newJA3 = ndpi_malloc(sizeof(ndpi_ja3_info));
                            newJA3->ja3 = known_flow_array[i].flow->ssh_tls.ja3_server;
                            newJA3->unsafe_cipher = known_flow_array[i].flow->ssh_tls.server_unsafe_cipher;
                            HASH_ADD_KEYPTR(hh, ja3ByHostFound->host_server_info_hasht,
                                newJA3->ja3, strlen(newJA3->ja3), newJA3);
                        }
                    }

                    HASH_FIND_STR(hostByJA3S_ht, known_flow_array[i].flow->ssh_tls.ja3_server, hostByJA3Found);
                    if (hostByJA3Found == NULL) {
                        ndpi_ip_dns* newHost = ndpi_malloc(sizeof(ndpi_ip_dns));

                        newHost->ip = known_flow_array[i].flow->dst_ip;
                        newHost->ip_string = known_flow_array[i].flow->dst_name;
                        newHost->dns_name = known_flow_array[i].flow->ssh_tls.server_info;;

                        ndpi_ja3_fingerprints_host* newElement = ndpi_malloc(sizeof(ndpi_ja3_fingerprints_host));
                        newElement->ja3 = known_flow_array[i].flow->ssh_tls.ja3_server;
                        newElement->unsafe_cipher = known_flow_array[i].flow->ssh_tls.server_unsafe_cipher;
                        newElement->ipToDNS_ht = NULL;

                        HASH_ADD_INT(newElement->ipToDNS_ht, ip, newHost);
                        HASH_ADD_KEYPTR(hh, hostByJA3S_ht, newElement->ja3, strlen(newElement->ja3),
                            newElement);
                    }
                    else {
                        ndpi_ip_dns* innerElement = NULL;

                        HASH_FIND_INT(hostByJA3Found->ipToDNS_ht, &(known_flow_array[i].flow->dst_ip), innerElement);
                        if (innerElement == NULL) {
                            ndpi_ip_dns* newInnerElement = ndpi_malloc(sizeof(ndpi_ip_dns));
                            newInnerElement->ip = known_flow_array[i].flow->dst_ip;
                            newInnerElement->ip_string = known_flow_array[i].flow->dst_name;
                            newInnerElement->dns_name = known_flow_array[i].flow->ssh_tls.server_info;
                            HASH_ADD_INT(hostByJA3Found->ipToDNS_ht, ip, newInnerElement);
                        }
                    }
                }
            }

            if (ja3ByHostsHashT) {
                ndpi_ja3_fingerprints_host* hostByJA3Element = NULL;
                ndpi_ja3_fingerprints_host* tmp3 = NULL;
                ndpi_ip_dns* innerHashEl = NULL;
                ndpi_ip_dns* tmp4 = NULL;

                if (verbose == 2) {
                  /* for each host the number of flow with a ja3 fingerprint is printed */
                    i = 1;

                    printw("JA3 Host Stats: \n");
                    printw("\t\t IP %-24s \t %-10s \n", "Address", "# JA3C");

                    for (ja3ByHost_element = ja3ByHostsHashT; ja3ByHost_element != NULL;
                        ja3ByHost_element = ja3ByHost_element->hh.next) {
                        num_ja3_ja4_client = HASH_COUNT(ja3ByHost_element->host_client_info_hasht);
                        num_ja3_server = HASH_COUNT(ja3ByHost_element->host_server_info_hasht);

                        if (num_ja3_ja4_client > 0) {
                            printw("\t%d\t %-24s \t %-7u\n",
                                i,
                                ja3ByHost_element->ip_string,
                                num_ja3_ja4_client
                            );
                            i++;
                        }

                    }
                }
                else if (verbose == 3) {
                    int i = 1;
                    int againstRepeat;
                    ndpi_ja3_fingerprints_host* hostByJA3Element = NULL;
                    ndpi_ja3_fingerprints_host* tmp3 = NULL;
                    ndpi_ip_dns* innerHashEl = NULL;
                    ndpi_ip_dns* tmp4 = NULL;

                    //for each host it is printted the JA3C and JA3S, along the server name (if any)
                    //and the security status

                    printw("JA3C/JA3S Host Stats: \n");
                    printw("\t%-7s %-24s %-34s %s\n", "", "IP", "JA3C", "JA3S");

                    //reminder
                    //ja3ByHostsHashT: hash table <ip, (ja3, ht_client, ht_server)>
                    //ja3ByHost_element: element of ja3ByHostsHashT
                    //info_of_element: element of the inner hash table of ja3ByHost_element
                    HASH_ITER(hh, ja3ByHostsHashT, ja3ByHost_element, tmp) {
                        num_ja3_ja4_client = HASH_COUNT(ja3ByHost_element->host_client_info_hasht);
                        num_ja3_server = HASH_COUNT(ja3ByHost_element->host_server_info_hasht);
                        againstRepeat = 0;
                        if (num_ja3_ja4_client > 0) {
                            HASH_ITER(hh, ja3ByHost_element->host_client_info_hasht, info_of_element, tmp2) {
                                printw("\t%-7d %-24s %s %s\n",
                                    i,
                                    ja3ByHost_element->ip_string,
                                    info_of_element->ja3,
                                    print_cipher(info_of_element->unsafe_cipher)
                                );
                                againstRepeat = 1;
                                i++;
                            }
                        }

                        if (num_ja3_server > 0) {
                            HASH_ITER(hh, ja3ByHost_element->host_server_info_hasht, info_of_element, tmp2) {
                                printw("\t%-7d %-24s %-34s %s %s %s%s%s\n",
                                    i,
                                    ja3ByHost_element->ip_string,
                                    "",
                                    info_of_element->ja3,
                                    print_cipher(info_of_element->unsafe_cipher),
                                    ja3ByHost_element->dns_name[0] ? "[" : "",
                                    ja3ByHost_element->dns_name,
                                    ja3ByHost_element->dns_name[0] ? "]" : ""
                                );
                                i++;
                            }
                        }
                    }

                    i = 1;

                    printw("\nIP/JA3 Distribution:\n");
                    printw("%-15s %-39s %-26s\n", "", "JA3", "IP");
                    HASH_ITER(hh, hostByJA3C_ht, hostByJA3Element, tmp3) {
                        againstRepeat = 0;
                        HASH_ITER(hh, hostByJA3Element->ipToDNS_ht, innerHashEl, tmp4) {
                            if (againstRepeat == 0) {
                                printw("\t%-7d JA3C %s",
                                    i,
                                    hostByJA3Element->ja3
                                );
                                printw("   %-15s %s\n",
                                    innerHashEl->ip_string,
                                    print_cipher(hostByJA3Element->unsafe_cipher)
                                );
                                againstRepeat = 1;
                                i++;
                            }
                            else {
                                printw("\t%45s", "");
                                printw("   %-15s %s\n",
                                    innerHashEl->ip_string,
                                    print_cipher(hostByJA3Element->unsafe_cipher)
                                );
                            }
                        }
                    }
                    HASH_ITER(hh, hostByJA3S_ht, hostByJA3Element, tmp3) {
                        againstRepeat = 0;
                        HASH_ITER(hh, hostByJA3Element->ipToDNS_ht, innerHashEl, tmp4) {
                            if (againstRepeat == 0) {
                                printw("\t%-7d JA3S %s",
                                    i,
                                    hostByJA3Element->ja3
                                );
                                printw("   %-15s %-10s %s%s%s\n",
                                    innerHashEl->ip_string,
                                    print_cipher(hostByJA3Element->unsafe_cipher),
                                    innerHashEl->dns_name[0] ? "[" : "",
                                    innerHashEl->dns_name,
                                    innerHashEl->dns_name[0] ? "]" : ""
                                );
                                againstRepeat = 1;
                                i++;
                            }
                            else {
                                printw("\t%45s", "");
                                printw("   %-15s %-10s %s%s%s\n",
                                    innerHashEl->ip_string,
                                    print_cipher(hostByJA3Element->unsafe_cipher),
                                    innerHashEl->dns_name[0] ? "[" : "",
                                    innerHashEl->dns_name,
                                    innerHashEl->dns_name[0] ? "]" : ""
                                );
                            }
                        }
                    }
                }
                printw("\n\n");

                //freeing the hash table
                HASH_ITER(hh, ja3ByHostsHashT, ja3ByHost_element, tmp) {
                    HASH_ITER(hh, ja3ByHost_element->host_client_info_hasht, info_of_element, tmp2) {
                        if (ja3ByHost_element->host_client_info_hasht)
                            HASH_DEL(ja3ByHost_element->host_client_info_hasht, info_of_element);
                        ndpi_free(info_of_element);
                    }
                    HASH_ITER(hh, ja3ByHost_element->host_server_info_hasht, info_of_element, tmp2) {
                        if (ja3ByHost_element->host_server_info_hasht)
                            HASH_DEL(ja3ByHost_element->host_server_info_hasht, info_of_element);
                        ndpi_free(info_of_element);
                    }
                    HASH_DEL(ja3ByHostsHashT, ja3ByHost_element);
                    ndpi_free(ja3ByHost_element);
                }

                HASH_ITER(hh, hostByJA3C_ht, hostByJA3Element, tmp3) {
                    HASH_ITER(hh, hostByJA3C_ht->ipToDNS_ht, innerHashEl, tmp4) {
                        if (hostByJA3Element->ipToDNS_ht)
                            HASH_DEL(hostByJA3Element->ipToDNS_ht, innerHashEl);
                        ndpi_free(innerHashEl);
                    }
                    HASH_DEL(hostByJA3C_ht, hostByJA3Element);
                    ndpi_free(hostByJA3Element);
                }

                hostByJA3Element = NULL;
                HASH_ITER(hh, hostByJA3S_ht, hostByJA3Element, tmp3) {
                    HASH_ITER(hh, hostByJA3S_ht->ipToDNS_ht, innerHashEl, tmp4) {
                        if (hostByJA3Element->ipToDNS_ht)
                            HASH_DEL(hostByJA3Element->ipToDNS_ht, innerHashEl);
                        ndpi_free(innerHashEl);
                    }
                    HASH_DEL(hostByJA3S_ht, hostByJA3Element);
                    ndpi_free(hostByJA3Element);
                }
            }
        }

        if (verbose == 4) {
            //how long the table could be
            unsigned int len_table_max = 1000;
                //number of element to delete when the table is full
            int toDelete = 10;
            struct hash_stats* hostsHashT = NULL;
            struct hash_stats* host_iter = NULL;
            struct hash_stats* tmp = NULL;
            int len_max = 0;

            for (i = 0; i < known_flow_count; i++) {

                if (known_flow_array[i].flow->host_server_name[0] != '\0') {

                    int len = strlen(known_flow_array[i].flow->host_server_name);
                    len_max = ndpi_max(len, len_max);

                    struct hash_stats* hostFound;
                    HASH_FIND_STR(hostsHashT, known_flow_array[i].flow->host_server_name, hostFound);

                    if (hostFound == NULL) {
                        struct hash_stats* newHost = (struct hash_stats*)ndpi_malloc(sizeof(hash_stats));
                        newHost->domain_name = known_flow_array[i].flow->host_server_name;
                        newHost->occurency = 1;
                        if (HASH_COUNT(hostsHashT) == len_table_max) {
                            int i = 0;
                            while (i <= toDelete) {

                                HASH_ITER(hh, hostsHashT, host_iter, tmp) {
                                    HASH_DEL(hostsHashT, host_iter);
                                    free(host_iter);
                                    i++;
                                }
                            }

                        }
                        HASH_ADD_KEYPTR(hh, hostsHashT, newHost->domain_name, strlen(newHost->domain_name), newHost);
                    }
                    else
                        hostFound->occurency++;


                }

                if (known_flow_array[i].flow->ssh_tls.server_info[0] != '\0') {

                    int len = strlen(known_flow_array[i].flow->host_server_name);
                    len_max = ndpi_max(len, len_max);

                    struct hash_stats* hostFound;
                    HASH_FIND_STR(hostsHashT, known_flow_array[i].flow->ssh_tls.server_info, hostFound);

                    if (hostFound == NULL) {
                        struct hash_stats* newHost = (struct hash_stats*)ndpi_malloc(sizeof(hash_stats));
                        newHost->domain_name = known_flow_array[i].flow->ssh_tls.server_info;
                        newHost->occurency = 1;

                        if ((HASH_COUNT(hostsHashT)) == len_table_max) {
                            int i = 0;
                            while (i < toDelete) {

                                HASH_ITER(hh, hostsHashT, host_iter, tmp) {
                                    HASH_DEL(hostsHashT, host_iter);
                                    ndpi_free(host_iter);
                                    i++;
                                }
                            }


                        }
                        HASH_ADD_KEYPTR(hh, hostsHashT, newHost->domain_name, strlen(newHost->domain_name), newHost);
                    }
                    else
                        hostFound->occurency++;


                }

                //sort the table by the least occurency
                HASH_SORT(hostsHashT, hash_stats_sort_to_order);
            }

            //sort the table in decreasing order to print
            HASH_SORT(hostsHashT, hash_stats_sort_to_print);

        //print the element of the hash table
            int j;
            HASH_ITER(hh, hostsHashT, host_iter, tmp) {

                printf("\t%s", host_iter->domain_name);
                //to print the occurency in aligned column
                int diff = len_max - strlen(host_iter->domain_name);
                for (j = 0; j <= diff + 5;j++)
                    printf(" ");
                printf("%d\n", host_iter->occurency);
            }
            printf("%s", "\n\n");

            //freeing the hash table
            HASH_ITER(hh, hostsHashT, host_iter, tmp) {
                HASH_DEL(hostsHashT, host_iter);
                ndpi_free(host_iter);
            }

        }

          /* Print all flows stats */

        qsort(known_flow_array, known_flow_count, sizeof(struct flow_info), cmpFlows);

        if (verbose > 1) {
#ifndef DIRECTION_BINS
            struct ndpi_bin* bins = (struct ndpi_bin*)ndpi_malloc(sizeof(struct ndpi_bin) * known_flow_count);
            u_int16_t* cluster_ids = (u_int16_t*)ndpi_malloc(sizeof(u_int16_t) * known_flow_count);
            u_int32_t num_flow_bins = 0;
#endif

            for (i = 0; i < known_flow_count; i++) {
#ifndef DIRECTION_BINS
                if (enable_doh_dot_detection) {
                  /* Discard flows with few packets per direction */
                    if ((known_flow_array[i].flow->src2dst_packets < 10)
                        || (known_flow_array[i].flow->dst2src_packets < 10)
                        /* Ignore flows for which we have not seen the beginning */
                        ) {
                        goto print_flow;
                    }

                    if (known_flow_array[i].flow->protocol == 6 /* TCP */) {
                      /* Discard flows with no SYN as we need to check ALPN */
                        if ((known_flow_array[i].flow->src2dst_syn_count == 0) || (known_flow_array[i].flow->dst2src_syn_count == 0)) {
                            goto print_flow;
                        }

                        if (known_flow_array[i].flow->detected_protocol.proto.master_protocol == NDPI_PROTOCOL_TLS) {
                            if ((known_flow_array[i].flow->src2dst_packets + known_flow_array[i].flow->dst2src_packets) < 40) {
                                goto print_flow; /* Too few packets for TLS negotiation etc */
                            }
                        }
                    }
                }

                if (bins && cluster_ids) {
                    u_int j;
                    u_int8_t not_empty;

                    if (enable_doh_dot_detection) {
                        not_empty = 0;

                        /* Check if bins are empty (and in this case discard it) */
                        for (j = 0; j < known_flow_array[i].flow->payload_len_bin.num_bins; j++)
                            if (known_flow_array[i].flow->payload_len_bin.u.bins8[j] != 0) {
                                not_empty = 1;
                                break;
                            }
                    }
                    else
                        not_empty = 1;

                    if (not_empty) {
                        memcpy(&bins[num_flow_bins], &known_flow_array[i].flow->payload_len_bin, sizeof(struct ndpi_bin));
                        ndpi_normalize_bin(&bins[num_flow_bins]);
                        num_flow_bins++;
                    }
                }
#endif

            print_flow:
                ncurses_print_flow(i + 1, known_flow_array[i].flow, known_flow_array[i].thread_id);
            }

#ifndef DIRECTION_BINS
            if (bins && cluster_ids && (num_bin_clusters > 0) && (num_flow_bins > 0)) {
                char buf[64];
                u_int j;
                struct ndpi_bin* centroids;

                if ((centroids = (struct ndpi_bin*)ndpi_malloc(sizeof(struct ndpi_bin) * num_bin_clusters)) != NULL) {
                    for (i = 0; i < num_bin_clusters; i++) {
                        ndpi_init_bin(&centroids[i], ndpi_bin_family32 /* Use 32 bit to avoid overlaps */,
                            bins[0].num_bins);
                    }

                    ndpi_cluster_bins(bins, num_flow_bins, num_bin_clusters, cluster_ids, centroids);

                    printw("\n"
                        "\tBin clusters\n"
                        "\t------------\n");

                    for (j = 0; j < num_bin_clusters; j++) {
                        u_int16_t num_printed = 0;
                        float max_similarity = 0;

                        for (i = 0; i < num_flow_bins; i++) {
                            float similarity, s;

                            if (cluster_ids[i] != j) continue;

                            if (num_printed == 0) {
                                printw("\tCluster %u [", j);
                                ncurses_print_bin(NULL, &centroids[j]);
                                printw("]\n");
                            }

                            printw("\t%u\t%-10s\t%s:%u <-> %s:%u\t[",
                                i,
                                ndpi_protocol2name(ndpi_thread_info[0].workflow->ndpi_struct,
                                    known_flow_array[i].flow->detected_protocol, buf, sizeof(buf)),
                                known_flow_array[i].flow->src_name,
                                ntohs(known_flow_array[i].flow->src_port),
                                known_flow_array[i].flow->dst_name,
                                ntohs(known_flow_array[i].flow->dst_port));

                            ncurses_print_bin(NULL, &bins[i]);
                            printw("][similarity: %f]",
                                (similarity = ndpi_bin_similarity(&centroids[j], &bins[i], 0, 0)));

                            if (known_flow_array[i].flow->host_server_name[0] != '\0') {
                                printw("[%s]", known_flow_array[i].flow->host_server_name);
                            }

                            if (enable_doh_dot_detection) {
                                if (((known_flow_array[i].flow->detected_protocol.proto.master_protocol == NDPI_PROTOCOL_TLS)
                                    || (known_flow_array[i].flow->detected_protocol.proto.app_protocol == NDPI_PROTOCOL_TLS)
                                    || (known_flow_array[i].flow->detected_protocol.proto.app_protocol == NDPI_PROTOCOL_DOH_DOT)
                                    )
                                    && known_flow_array[i].flow->ssh_tls.advertised_alpns /* ALPN */
                                    ) {
                                    if (check_bin_doh_similarity(&bins[i], &s))
                                        printw("[DoH (%f distance)]", s);
                                    else
                                        printw("[NO DoH (%f distance)]", s);
                                }
                                else {
                                    if (known_flow_array[i].flow->ssh_tls.advertised_alpns == NULL)
                                        printw("[NO DoH check: missing ALPN]");
                                }
                            }

                            printw("\n");
                            num_printed++;
                            if (similarity > max_similarity) max_similarity = similarity;
                        }

                        if (num_printed) {
                            printw("\tMax similarity: %f\n", max_similarity);
                            printw("\n");
                        }
                    }

                    for (i = 0; i < num_bin_clusters; i++) {
                        ndpi_free_bin(&centroids[i]);
                    }

                    ndpi_free(centroids);
                }
            }
            if (bins)
                ndpi_free(bins);
            if (cluster_ids)
                ndpi_free(cluster_ids);
#endif
        }

        if (unknown_flow_count > 0) {
            printw("\n\nUndetected flows:%s\n",
                undetected_flows_deleted ? " (expired flows are not listed below)" : "");
            qsort(unknown_flow_array, unknown_flow_count, sizeof(struct flow_info), cmpFlows);

            for (i = 0; i < unknown_flow_count; i++) {
                ncurses_print_flow(i + 1, unknown_flow_array[i].flow, unknown_flow_array[i].thread_id);
            }
        }
    }
    else if (csv_fp != NULL) {
        unsigned int i;
        for (i = 0; i < known_flow_count; i++) {
            ncurses_print_flow(i + 1, known_flow_array[i].flow, known_flow_array[i].thread_id);
        }
    }

    if (serialization_fp != NULL &&
        serialization_format != ndpi_serialization_format_unknown)
    {
        unsigned int i;
        for (i = 0; i < known_flow_count; i++) {
            ncurses_print_flow_serialized(known_flow_array[i].flow);
        }
        for (i = 0; i < unknown_flow_count; i++) {
            ncurses_print_flow_serialized(unknown_flow_array[i].flow);
        }
    }
}

char* ncurses_print_cipher(ndpi_cipher_weakness c) {
    switch (c) {
    case ndpi_cipher_insecure:
        return(" (INSECURE)");
        break;

    case ndpi_cipher_weak:
        return(" (WEAK)");
        break;

    default:
        return("");
    }
}

void ncurses_print_flow(u_int32_t id, struct ndpi_flow_info* flow, u_int16_t thread_id) {
    u_int8_t known_tls;
    char buf[32], buf1[64];
    char buf_ver[16];
    char l4_proto_name[32];
    u_int i;

    printw("\t%u", id);

    printw("\t%s ", ndpi_get_ip_proto_name(flow->protocol, l4_proto_name, sizeof(l4_proto_name)));

    printw("%s%s%s:%u %s %s%s%s:%u ",
        (flow->ip_version == 6) ? "[" : "",
        flow->src_name, (flow->ip_version == 6) ? "]" : "", ntohs(flow->src_port),
        flow->bidirectional ? "<->" : "->",
        (flow->ip_version == 6) ? "[" : "",
        flow->dst_name, (flow->ip_version == 6) ? "]" : "", ntohs(flow->dst_port)
    );

    if (flow->vlan_id > 0) printw("[VLAN: %u]", flow->vlan_id);
    if (enable_payload_analyzer) printw("[flowId: %u]", flow->flow_id);

    if (enable_flow_stats) {
      /* Print entropy values for monitored flows. */
        flowGetBDMeanandVariance(flow);
        printw("[score: %.4f]", flow->entropy->score);
    }

    printw("[proto: ");
    if (flow->tunnel_type != ndpi_no_tunnel)
        printw("%s:", ndpi_tunnel2str(flow->tunnel_type));

    printw("%s/%s][IP: %u/%s]",
        ndpi_protocol2id(flow->detected_protocol, buf, sizeof(buf)),
        ndpi_protocol2name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
            flow->detected_protocol, buf1, sizeof(buf1)),
        flow->detected_protocol.protocol_by_ip,
        ndpi_get_proto_name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
            flow->detected_protocol.protocol_by_ip));

    if (flow->multimedia_flow_type != ndpi_multimedia_unknown_flow) {
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

        printw("[Stream Content: %s]", content);
    }

    printw("[%s]",
        ndpi_is_encrypted_proto(ndpi_thread_info[thread_id].workflow->ndpi_struct,
            flow->detected_protocol) ? "Encrypted" : "ClearText");

    printw("[Confidence: %s]", ndpi_confidence_get_name(flow->confidence));

    if (flow->fpc.proto.master_protocol == NDPI_PROTOCOL_UNKNOWN) {
        printw("[FPC: %u/%s, ",
            flow->fpc.proto.app_protocol,
            ndpi_get_proto_name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
                flow->fpc.proto.app_protocol));
    }
    else {
        printw("[FPC: %u.%u/%s.%s, ",
            flow->fpc.proto.master_protocol,
            flow->fpc.proto.app_protocol,
            ndpi_get_proto_name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
                flow->fpc.proto.master_protocol),
            ndpi_get_proto_name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
                flow->fpc.proto.app_protocol));
    }
    printw("Confidence: %s]",
        ndpi_fpc_confidence_get_name(flow->fpc.confidence));

    /* If someone wants to have the num_dissector_calls variable per flow, he can print it here.
       Disabled by default to avoid too many diffs in the unit tests...
    */
#if 0
    printw("[Num calls: %d]", flow->num_dissector_calls);
#endif
    printw("[DPI packets: %d]", flow->dpi_packets);

    if (flow->detected_protocol.category != 0)
        printw("[cat: %s/%u]",
            ndpi_category_get_name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
                flow->detected_protocol.category),
            (unsigned int)flow->detected_protocol.category);

    printw("[%u pkts/%llu bytes ", flow->src2dst_packets, (long long unsigned int) flow->src2dst_bytes);
    printw("%s %u pkts/%llu bytes]",
        (flow->dst2src_packets > 0) ? "<->" : "->",
        flow->dst2src_packets, (long long unsigned int) flow->dst2src_bytes);

    printw("[Goodput ratio: %.0f/%.0f]",
        100.0 * ((float)flow->src2dst_goodput_bytes / (float)(flow->src2dst_bytes + 1)),
        100.0 * ((float)flow->dst2src_goodput_bytes / (float)(flow->dst2src_bytes + 1)));

    if (flow->last_seen_ms > flow->first_seen_ms)
        printw("[%.2f sec]", ((float)(flow->last_seen_ms - flow->first_seen_ms)) / (float)1000);
    else
        printw("[< 1 sec]");

    if (flow->telnet.username)  printw("[Username: %s]", flow->telnet.username);
    if (flow->telnet.password)  printw("[Password: %s]", flow->telnet.password);

    if (flow->host_server_name[0] != '\0') printw("[Hostname/SNI: %s]", flow->host_server_name);

    switch (flow->info_type)
    {
    case INFO_INVALID:
        break;

    case INFO_GENERIC:
        if (flow->info[0] != '\0')
        {
            printw("[%s]", flow->info);
        }
        break;

    case INFO_KERBEROS:
        if (flow->kerberos.domain[0] != '\0' ||
            flow->kerberos.hostname[0] != '\0' ||
            flow->kerberos.username[0] != '\0')
        {
            printw("[%s%s%s%s]",
                flow->kerberos.domain,
                (flow->kerberos.hostname[0] != '\0' ||
                    flow->kerberos.username[0] != '\0' ? "\\" : ""),
                flow->kerberos.hostname,
                flow->kerberos.username);
        }
        break;

    case INFO_SOFTETHER:
        if (flow->softether.ip[0] != '\0')
        {
            printw("[Client IP: %s]", flow->softether.ip);
        }
        if (flow->softether.port[0] != '\0')
        {
            printw("[Client Port: %s]", flow->softether.port);
        }
        if (flow->softether.hostname[0] != '\0')
        {
            printw("[Hostname: %s]", flow->softether.hostname);
        }
        if (flow->softether.fqdn[0] != '\0')
        {
            printw("[FQDN: %s]", flow->softether.fqdn);
        }
        break;

    case INFO_TIVOCONNECT:
        if (flow->tivoconnect.identity_uuid[0] != '\0')
        {
            printw("[UUID: %s]", flow->tivoconnect.identity_uuid);
        }
        if (flow->tivoconnect.machine[0] != '\0')
        {
            printw("[Machine: %s]", flow->tivoconnect.machine);
        }
        if (flow->tivoconnect.platform[0] != '\0')
        {
            printw("[Platform: %s]", flow->tivoconnect.platform);
        }
        if (flow->tivoconnect.services[0] != '\0')
        {
            printw("[Services: %s]", flow->tivoconnect.services);
        }
        break;

    case INFO_NATPMP:
        if (flow->natpmp.internal_port != 0 && flow->natpmp.ip[0] != '\0')
        {
            printw("[Result: %u][Internal Port: %u][External Port: %u][External Address: %s]",
                flow->natpmp.result_code, flow->natpmp.internal_port, flow->natpmp.external_port,
                flow->natpmp.ip);
        }
        break;

    case INFO_FTP_IMAP_POP_SMTP:
        if (flow->ftp_imap_pop_smtp.username[0] != '\0')
        {
            printw("[User: %s][Pwd: %s]",
                flow->ftp_imap_pop_smtp.username,
                flow->ftp_imap_pop_smtp.password);
            if (flow->ftp_imap_pop_smtp.auth_failed != 0)
            {
                printw("[%s]", "Auth Failed");
            }
        }
        break;
    }

    if (flow->ssh_tls.advertised_alpns)
        printw("[(Advertised) ALPNs: %s]", flow->ssh_tls.advertised_alpns);

    if (flow->ssh_tls.negotiated_alpn)
        printw("[(Negotiated) ALPN: %s]", flow->ssh_tls.negotiated_alpn);

    if (flow->ssh_tls.tls_supported_versions)
        printw("[TLS Supported Versions: %s]", flow->ssh_tls.tls_supported_versions);

    if (flow->mining.currency[0] != '\0') printw("[currency: %s]", flow->mining.currency);

    if (flow->dns.geolocation_iata_code[0] != '\0') printw("[GeoLocation: %s]", flow->dns.geolocation_iata_code);

    if ((flow->src2dst_packets + flow->dst2src_packets) > 5) {
        if (flow->iat_c_to_s && flow->iat_s_to_c) {
            float data_ratio = ndpi_data_ratio(flow->src2dst_bytes, flow->dst2src_bytes);

            printw("[bytes ratio: %.3f (%s)]", data_ratio, ndpi_data_ratio2str(data_ratio));

            /* IAT (Inter Arrival Time) */
            printw("[IAT c2s/s2c min/avg/max/stddev: %llu/%llu %.0f/%.0f %llu/%llu %.0f/%.0f]",
                (unsigned long long int)ndpi_data_min(flow->iat_c_to_s),
                (unsigned long long int)ndpi_data_min(flow->iat_s_to_c),
                (float)ndpi_data_average(flow->iat_c_to_s), (float)ndpi_data_average(flow->iat_s_to_c),
                (unsigned long long int)ndpi_data_max(flow->iat_c_to_s),
                (unsigned long long int)ndpi_data_max(flow->iat_s_to_c),
                (float)ndpi_data_stddev(flow->iat_c_to_s), (float)ndpi_data_stddev(flow->iat_s_to_c));

            /* Packet Length */
            printw("[Pkt Len c2s/s2c min/avg/max/stddev: %llu/%llu %.0f/%.0f %llu/%llu %.0f/%.0f]",
                (unsigned long long int)ndpi_data_min(flow->pktlen_c_to_s),
                (unsigned long long int)ndpi_data_min(flow->pktlen_s_to_c),
                ndpi_data_average(flow->pktlen_c_to_s), ndpi_data_average(flow->pktlen_s_to_c),
                (unsigned long long int)ndpi_data_max(flow->pktlen_c_to_s),
                (unsigned long long int)ndpi_data_max(flow->pktlen_s_to_c),
                ndpi_data_stddev(flow->pktlen_c_to_s), ndpi_data_stddev(flow->pktlen_s_to_c));
        }
    }

    ncurses_print_ndpi_address_port_file("Mapped IP/Port", &flow->stun.mapped_address);
    ncurses_print_ndpi_address_port_file("Peer IP/Port", &flow->stun.peer_address);
    ncurses_print_ndpi_address_port_file("Relayed IP/Port", &flow->stun.relayed_address);
    ncurses_print_ndpi_address_port_file("Rsp Origin IP/Port", &flow->stun.response_origin);
    ncurses_print_ndpi_address_port_file("Other IP/Port", &flow->stun.other_address);

    if (flow->http.url[0] != '\0') {
        ndpi_risk_enum risk = ndpi_validate_url(flow->http.url);

        if (risk != NDPI_NO_RISK)
            NDPI_SET_BIT(flow->risk, risk);

        printw("[URL: %s]", flow->http.url);
    }

    if (flow->http.response_status_code)
        printw("[StatusCode: %u]", flow->http.response_status_code);

    if (flow->http.request_content_type[0] != '\0')
        printw("[Req Content-Type: %s]", flow->http.request_content_type);

    if (flow->http.content_type[0] != '\0')
        printw("[Content-Type: %s]", flow->http.content_type);

    if (flow->http.nat_ip[0] != '\0')
        printw("[Nat-IP: %s]", flow->http.nat_ip);

    if (flow->http.server[0] != '\0')
        printw("[Server: %s]", flow->http.server);

    if (flow->http.user_agent[0] != '\0')
        printw("[User-Agent: %s]", flow->http.user_agent);

    if (flow->http.filename[0] != '\0')
        printw("[Filename: %s]", flow->http.filename);

    if (flow->risk) {
        u_int i;
        u_int16_t cli_score, srv_score;
        printw("[Risk: ");

        for (i = 0; i < NDPI_MAX_RISK; i++)
            if (NDPI_ISSET_BIT(flow->risk, i))
                printw("** %s **", ndpi_risk2str(i));

        printw("]");

        printw("[Risk Score: %u]", ndpi_risk2score(flow->risk, &cli_score, &srv_score));

        if (flow->risk_str)
            printw("[Risk Info: %s]", flow->risk_str);
    }

    if (flow->ssh_tls.ssl_version != 0) printw("[%s]", ndpi_ssl_version2str(buf_ver, sizeof(buf_ver),
        flow->ssh_tls.ssl_version, &known_tls));

    if (flow->ssh_tls.quic_version != 0) printw("[QUIC ver: %s]", ndpi_quic_version2str(buf_ver, sizeof(buf_ver),
        flow->ssh_tls.quic_version));

    if (flow->ssh_tls.client_hassh[0] != '\0') printw("[HASSH-C: %s]", flow->ssh_tls.client_hassh);

    if (flow->ssh_tls.ja3_client[0] != '\0') printw("[JA3C: %s%s]", flow->ssh_tls.ja3_client,
        ncurses_print_cipher(flow->ssh_tls.client_unsafe_cipher));

    if (flow->ssh_tls.ja4_client[0] != '\0') printw("[JA4: %s%s]", flow->ssh_tls.ja4_client,
        ncurses_print_cipher(flow->ssh_tls.client_unsafe_cipher));

    if (flow->ssh_tls.ja4_client_raw != NULL) printw("[JA4_r: %s]", flow->ssh_tls.ja4_client_raw);

    if (flow->ssh_tls.server_info[0] != '\0') printw("[Server: %s]", flow->ssh_tls.server_info);

    if (flow->ssh_tls.server_names) printw("[ServerNames: %s]", flow->ssh_tls.server_names);
    if (flow->ssh_tls.server_hassh[0] != '\0') printw("[HASSH-S: %s]", flow->ssh_tls.server_hassh);

    if (flow->ssh_tls.ja3_server[0] != '\0') printw("[JA3S: %s%s]", flow->ssh_tls.ja3_server,
        ncurses_print_cipher(flow->ssh_tls.server_unsafe_cipher));

    if (flow->ssh_tls.tls_issuerDN)  printw("[Issuer: %s]", flow->ssh_tls.tls_issuerDN);
    if (flow->ssh_tls.tls_subjectDN) printw("[Subject: %s]", flow->ssh_tls.tls_subjectDN);

    if (flow->ssh_tls.encrypted_sni.esni) {
        char unknown_cipher[8];
        printw("[ESNI: %s]", flow->ssh_tls.encrypted_sni.esni);
        printw("[ESNI Cipher: %s]",
            ndpi_cipher2str(flow->ssh_tls.encrypted_sni.cipher_suite, unknown_cipher));
    }

    if (flow->ssh_tls.encrypted_ch.version != 0) {
        printw("[ECH: version 0x%x]", flow->ssh_tls.encrypted_ch.version);
    }

    if (flow->ssh_tls.sha1_cert_fingerprint_set) {
        printw("[Certificate SHA-1: ");
        for (i = 0; i < 20; i++)
            printw("%s%02X", (i > 0) ? ":" : "",
                flow->ssh_tls.sha1_cert_fingerprint[i] & 0xFF);
        printw("]");
    }

#ifdef HEURISTICS_CODE
    if (flow->ssh_tls.browser_heuristics.is_safari_tls)  printw("[Safari]");
    if (flow->ssh_tls.browser_heuristics.is_firefox_tls) printw("[Firefox]");
    if (flow->ssh_tls.browser_heuristics.is_chrome_tls)  printw("[Chrome]");
#endif

    if (flow->ssh_tls.notBefore && flow->ssh_tls.notAfter) {
        char notBefore[32], notAfter[32];
        struct tm a, b;
        struct tm* before = ndpi_gmtime_r(&flow->ssh_tls.notBefore, &a);
        struct tm* after = ndpi_gmtime_r(&flow->ssh_tls.notAfter, &b);

        strftime(notBefore, sizeof(notBefore), "%Y-%m-%d %H:%M:%S", before);
        strftime(notAfter, sizeof(notAfter), "%Y-%m-%d %H:%M:%S", after);

        printw("[Validity: %s - %s]", notBefore, notAfter);
    }

    char unknown_cipher[8];
    if (flow->ssh_tls.server_cipher != '\0')
    {
        printw("[Cipher: %s]", ndpi_cipher2str(flow->ssh_tls.server_cipher, unknown_cipher));
    }
    if (flow->bittorent_hash != NULL) printw("[BT Hash: %s]", flow->bittorent_hash);
    if (flow->dhcp_fingerprint != NULL) printw("[DHCP Fingerprint: %s]", flow->dhcp_fingerprint);
    if (flow->dhcp_class_ident) printw("[DHCP Class Ident: %s]",
        flow->dhcp_class_ident);

    if (flow->has_human_readeable_strings) printw("[PLAIN TEXT (%s)]",
        flow->human_readeable_string_buffer);

#ifdef DIRECTION_BINS
    ncurses_print_bin("Plen c2s", &flow->payload_len_bin_src2dst);
    ncurses_print_bin("Plen s2c", &flow->payload_len_bin_dst2src);
#else
    ncurses_print_bin("Plen Bins", &flow->payload_len_bin);
#endif

    if (flow->flow_payload && (flow->flow_payload_len > 0)) {
        u_int i;

        printw("[Payload: ");

        for (i = 0; i < flow->flow_payload_len; i++)
            printw("%c", ndpi_isspace(flow->flow_payload[i]) ? '.' : flow->flow_payload[i]);

        printw("]");
    }

    printw("\n");
}

void ncurses_print_flow_serialized(struct ndpi_flow_info* flow)
{
    char* json_str = NULL;
    u_int32_t json_str_len = 0;
    ndpi_serializer* const serializer = &flow->ndpi_flow_serializer;
    //float data_ratio = ndpi_data_ratio(flow->src2dst_bytes, flow->dst2src_bytes);
    double f = (double)flow->first_seen_ms, l = (double)flow->last_seen_ms;
    float data_ratio = ndpi_data_ratio(flow->src2dst_bytes, flow->dst2src_bytes);

    ndpi_serialize_string_uint32(serializer, "flow_id", flow->flow_id);
    ndpi_serialize_string_double(serializer, "first_seen", f / 1000., "%.3f");
    ndpi_serialize_string_double(serializer, "last_seen", l / 1000., "%.3f");
    ndpi_serialize_string_double(serializer, "duration", (l - f) / 1000.0, "%.3f");
    ndpi_serialize_string_uint32(serializer, "vlan_id", flow->vlan_id);
    ndpi_serialize_string_uint32(serializer, "bidirectional", flow->bidirectional);

    /* XFER Packets/Bytes */
    ndpi_serialize_start_of_block(serializer, "xfer");
    ndpi_serialize_string_float(serializer, "data_ratio", data_ratio, "%.3f");
    ndpi_serialize_string_string(serializer, "data_ratio_str", ndpi_data_ratio2str(data_ratio));
    ndpi_serialize_string_uint32(serializer, "src2dst_packets", flow->src2dst_packets);
    ndpi_serialize_string_uint64(serializer, "src2dst_bytes",
        (u_int64_t)flow->src2dst_bytes);
    ndpi_serialize_string_uint64(serializer, "src2dst_goodput_bytes",
        (u_int64_t)flow->src2dst_goodput_bytes);
    ndpi_serialize_string_uint32(serializer, "dst2src_packets", flow->dst2src_packets);
    ndpi_serialize_string_uint64(serializer, "dst2src_bytes",
        (u_int64_t)flow->dst2src_bytes);
    ndpi_serialize_string_uint64(serializer, "dst2src_goodput_bytes",
        (u_int64_t)flow->dst2src_goodput_bytes);
    ndpi_serialize_end_of_block(serializer);

    /* IAT (Inter Arrival Time) */
    ndpi_serialize_start_of_block(serializer, "iat");
    ndpi_serialize_string_uint32(serializer, "flow_min", ndpi_data_min(flow->iat_flow));
    ndpi_serialize_string_float(serializer, "flow_avg",
        ndpi_data_average(flow->iat_flow), "%.1f");
    ndpi_serialize_string_uint32(serializer, "flow_max", ndpi_data_max(flow->iat_flow));
    ndpi_serialize_string_float(serializer, "flow_stddev",
        ndpi_data_stddev(flow->iat_flow), "%.1f");

    ndpi_serialize_string_uint32(serializer, "c_to_s_min",
        ndpi_data_min(flow->iat_c_to_s));
    ndpi_serialize_string_float(serializer, "c_to_s_avg",
        ndpi_data_average(flow->iat_c_to_s), "%.1f");
    ndpi_serialize_string_uint32(serializer, "c_to_s_max",
        ndpi_data_max(flow->iat_c_to_s));
    ndpi_serialize_string_float(serializer, "c_to_s_stddev",
        ndpi_data_stddev(flow->iat_c_to_s), "%.1f");

    ndpi_serialize_string_uint32(serializer, "s_to_c_min",
        ndpi_data_min(flow->iat_s_to_c));
    ndpi_serialize_string_float(serializer, "s_to_c_avg",
        ndpi_data_average(flow->iat_s_to_c), "%.1f");
    ndpi_serialize_string_uint32(serializer, "s_to_c_max",
        ndpi_data_max(flow->iat_s_to_c));
    ndpi_serialize_string_float(serializer, "s_to_c_stddev",
        ndpi_data_stddev(flow->iat_s_to_c), "%.1f");
    ndpi_serialize_end_of_block(serializer);

    /* Packet Length */
    ndpi_serialize_start_of_block(serializer, "pktlen");
    ndpi_serialize_string_uint32(serializer, "c_to_s_min",
        ndpi_data_min(flow->pktlen_c_to_s));
    ndpi_serialize_string_float(serializer, "c_to_s_avg",
        ndpi_data_average(flow->pktlen_c_to_s), "%.1f");
    ndpi_serialize_string_uint32(serializer, "c_to_s_max",
        ndpi_data_max(flow->pktlen_c_to_s));
    ndpi_serialize_string_float(serializer, "c_to_s_stddev",
        ndpi_data_stddev(flow->pktlen_c_to_s), "%.1f");

    ndpi_serialize_string_uint32(serializer, "s_to_c_min",
        ndpi_data_min(flow->pktlen_s_to_c));
    ndpi_serialize_string_float(serializer, "s_to_c_avg",
        ndpi_data_average(flow->pktlen_s_to_c), "%.1f");
    ndpi_serialize_string_uint32(serializer, "s_to_c_max",
        ndpi_data_max(flow->pktlen_s_to_c));
    ndpi_serialize_string_float(serializer, "s_to_c_stddev",
        ndpi_data_stddev(flow->pktlen_s_to_c), "%.1f");
    ndpi_serialize_end_of_block(serializer);

    /* TCP flags */
    ndpi_serialize_start_of_block(serializer, "tcp_flags");
    ndpi_serialize_string_int32(serializer, "cwr_count", flow->cwr_count);
    ndpi_serialize_string_int32(serializer, "ece_count", flow->ece_count);
    ndpi_serialize_string_int32(serializer, "urg_count", flow->urg_count);
    ndpi_serialize_string_int32(serializer, "ack_count", flow->ack_count);
    ndpi_serialize_string_int32(serializer, "psh_count", flow->psh_count);
    ndpi_serialize_string_int32(serializer, "rst_count", flow->rst_count);
    ndpi_serialize_string_int32(serializer, "syn_count", flow->syn_count);
    ndpi_serialize_string_int32(serializer, "fin_count", flow->fin_count);

    ndpi_serialize_string_int32(serializer, "src2dst_cwr_count", flow->src2dst_cwr_count);
    ndpi_serialize_string_int32(serializer, "src2dst_ece_count", flow->src2dst_ece_count);
    ndpi_serialize_string_int32(serializer, "src2dst_urg_count", flow->src2dst_urg_count);
    ndpi_serialize_string_int32(serializer, "src2dst_ack_count", flow->src2dst_ack_count);
    ndpi_serialize_string_int32(serializer, "src2dst_psh_count", flow->src2dst_psh_count);
    ndpi_serialize_string_int32(serializer, "src2dst_rst_count", flow->src2dst_rst_count);
    ndpi_serialize_string_int32(serializer, "src2dst_syn_count", flow->src2dst_syn_count);
    ndpi_serialize_string_int32(serializer, "src2dst_fin_count", flow->src2dst_fin_count);

    ndpi_serialize_string_int32(serializer, "dst2src_cwr_count", flow->dst2src_cwr_count);
    ndpi_serialize_string_int32(serializer, "dst2src_ece_count", flow->dst2src_ece_count);
    ndpi_serialize_string_int32(serializer, "dst2src_urg_count", flow->dst2src_urg_count);
    ndpi_serialize_string_int32(serializer, "dst2src_ack_count", flow->dst2src_ack_count);
    ndpi_serialize_string_int32(serializer, "dst2src_psh_count", flow->dst2src_psh_count);
    ndpi_serialize_string_int32(serializer, "dst2src_rst_count", flow->dst2src_rst_count);
    ndpi_serialize_string_int32(serializer, "dst2src_syn_count", flow->dst2src_syn_count);
    ndpi_serialize_string_int32(serializer, "dst2src_fin_count", flow->dst2src_fin_count);
    ndpi_serialize_end_of_block(serializer);

    /* TCP window */
    ndpi_serialize_string_uint32(serializer, "c_to_s_init_win", flow->c_to_s_init_win);
    ndpi_serialize_string_uint32(serializer, "s_to_c_init_win", flow->s_to_c_init_win);

    json_str = ndpi_serializer_get_buffer(serializer, &json_str_len);
    if (json_str == NULL || json_str_len == 0)
    {
        printw("ERROR: nDPI serialization failed\n");
        exit(-1);
    }

    fprintf(serialization_fp, "%.*s\n", (int)json_str_len, json_str);
}

void ncurses_print_bin(const char* label, struct ndpi_bin* b) {
    u_int16_t i;
    const char* sep = label ? "," : ";";

    ndpi_normalize_bin(b);

    if (label) printw("[%s: ", label);

    for (i = 0; i < b->num_bins; i++) {
        switch (b->family) {
        case ndpi_bin_family8:
            printw("%s%u", (i > 0) ? sep : "", b->u.bins8[i]);
            break;
        case ndpi_bin_family16:
            printw("%s%u", (i > 0) ? sep : "", b->u.bins16[i]);
            break;
        case ndpi_bin_family32:
            printw("%s%u", (i > 0) ? sep : "", b->u.bins32[i]);
            break;
        case ndpi_bin_family64:
            printw("%s%llu", (i > 0) ? sep : "", (unsigned long long)b->u.bins64[i]);
            break;
        }
    }

    if (label) printw("]");
}

void ncurses_print_ndpi_address_port_file(const char* label, ndpi_address_port* ap) {
    if (ap->port != 0) {
        char buf[INET6_ADDRSTRLEN];

        if (ap->is_ipv6) {
            inet_ntop(AF_INET6, &ap->address, buf, sizeof(buf));
            printw("[%s: [%s]:%u]", label, buf, ap->port);
        }
        else {
            inet_ntop(AF_INET, &ap->address, buf, sizeof(buf));
            printw("[%s: %s:%u]", label, buf, ap->port);
        }
    }
}
