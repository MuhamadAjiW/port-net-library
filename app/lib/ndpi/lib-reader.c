#include "../../include/lib-reader.h"

/* *********************************************** */

/**
 * @brief Ports stats
 */
void port_stats_walker(const void* node, ndpi_VISIT which, int depth, void* user_data) {
    if ((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
        struct ndpi_flow_info* flow = *(struct ndpi_flow_info**)node;
        u_int16_t thread_id = *(int*)user_data;
        u_int16_t sport, dport;
        char proto[16];

        (void)depth;

        sport = ntohs(flow->src_port), dport = ntohs(flow->dst_port);

        /* get app level protocol */
        if (flow->detected_protocol.proto.master_protocol) {
            ndpi_protocol2name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
                flow->detected_protocol, proto, sizeof(proto));
        }
        else {
            strncpy(proto, ndpi_get_proto_name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
                flow->detected_protocol.proto.app_protocol), sizeof(proto) - 1);
            proto[sizeof(proto) - 1] = '\0';
        }

        if (flow->protocol == IPPROTO_TCP
            && (flow->src2dst_packets == 1) && (flow->dst2src_packets == 0)) {
            updateScanners(&scannerHosts, flow->src_ip, flow->ip_version, dport);
        }

        receivers_update(&receivers, flow->dst_ip, flow->ip_version,
            flow->src2dst_packets, &topReceivers);

        port_stats_update(&srcStats, sport, flow->src_ip, flow->ip_version,
            flow->src2dst_packets, flow->src2dst_bytes, proto);

        port_stats_update(&dstStats, dport, flow->dst_ip, flow->ip_version,
            flow->dst2src_packets, flow->dst2src_bytes, proto);
    }
}

int port_stats_sort(void* _a, void* _b) {
    struct port_stats* a = (struct port_stats*)_a;
    struct port_stats* b = (struct port_stats*)_b;

    if (b->num_pkts == 0 && a->num_pkts == 0)
        return(b->num_flows - a->num_flows);

    return(b->num_pkts - a->num_pkts);
}

void port_stats_delete(struct port_stats* stats) {
    struct port_stats* current_port, * tmp;

    HASH_ITER(hh, stats, current_port, tmp) {
        HASH_DEL(stats, current_port);
        ip_tree_free(current_port->addr_tree);
        ndpi_free(current_port);
    }
}

void port_stats_update(struct port_stats** stats, u_int32_t port,
    u_int32_t addr, u_int8_t version,
    u_int32_t num_pkts, u_int32_t num_bytes,
    const char* proto) {

    struct port_stats* s = NULL;
    int count = 0;

    HASH_FIND_INT(*stats, &port, s);
    if (s == NULL) {
        s = (struct port_stats*)ndpi_calloc(1, sizeof(struct port_stats));
        if (!s) return;

        s->port = port, s->num_pkts = num_pkts, s->num_bytes = num_bytes;
        s->num_addr = 1, s->cumulative_addr = 1; s->num_flows = 1;

        ip_update_top(addr, version, proto, 1, s->top_ip_addrs, MAX_NUM_IP_ADDRESS);

        s->addr_tree = (addr_node*)ndpi_malloc(sizeof(addr_node));
        if (!s->addr_tree) {
            ndpi_free(s);
            return;
        }

        s->addr_tree->addr = addr;
        s->addr_tree->version = version;
        strncpy(s->addr_tree->proto, proto, sizeof(s->addr_tree->proto) - 1);
        s->addr_tree->proto[sizeof(s->addr_tree->proto) - 1] = '\0';
        s->addr_tree->count = 1;
        s->addr_tree->left = NULL;
        s->addr_tree->right = NULL;

        HASH_ADD_INT(*stats, port, s);
    }
    else {
        count = ip_tree_update(addr, version, &(*s).addr_tree, proto);

        if (count == UPDATED_TREE) s->num_addr++;

        if (count) {
            s->cumulative_addr++;
            ip_update_top(addr, version, proto, count, s->top_ip_addrs, MAX_NUM_IP_ADDRESS);
        }

        s->num_pkts += num_pkts, s->num_bytes += num_bytes, s->num_flows++;
    }
}

void port_stats_print(struct port_stats* stats) {
    struct port_stats* s, * tmp;
    char addr_name[48];
    int i = 0, j = 0;

    HASH_ITER(hh, stats, s, tmp) {
        i++;
        printf("\t%2d\tPort %5u\t[%u IP address(es)/%u flows/%u pkts/%u bytes]\n\t\tTop IP Stats:\n",
            i, s->port, s->num_addr, s->num_flows, s->num_pkts, s->num_bytes);

        qsort(&s->top_ip_addrs[0], MAX_NUM_IP_ADDRESS, sizeof(struct info_pair), info_pair_cmp);

        for (j = 0; j < MAX_NUM_IP_ADDRESS; j++) {
            if (s->top_ip_addrs[j].count != 0) {
                if (s->top_ip_addrs[j].version == IPVERSION) {
                    inet_ntop(AF_INET, &(s->top_ip_addrs[j].addr), addr_name, sizeof(addr_name));
                }
                else {
                    inet_ntop(AF_INET6, &(s->top_ip_addrs[j].addr), addr_name, sizeof(addr_name));
                }

                printf("\t\t%-36s ~ %.2f%%\n", addr_name,
                    ((s->top_ip_addrs[j].count) * 100.0) / s->cumulative_addr);
            }
        }

        printf("\n");
        if (i >= 10) break;
    }
}

/* *********************************************** */

/**
 * @brief Ip Tree
 */
void ip_tree_free(addr_node* root) {
    if (root == NULL)
        return;

    ip_tree_free(root->left);
    ip_tree_free(root->right);
    ndpi_free(root);
}

int ip_tree_update(u_int32_t key, u_int8_t version,
    addr_node** vrootp, const char* proto) {
    addr_node* q;
    addr_node** rootp = vrootp;

    if (rootp == (addr_node**)0)
        return 0;

    while (*rootp != (addr_node*)0) {
      /* Knuth's T1: */
        if ((version == (*rootp)->version) && (key == (*rootp)->addr)) {
          /* T2: */
            return ++((*rootp)->count);
        }

        rootp = (key < (*rootp)->addr) ?
            &(*rootp)->left :                /* T3: follow left branch */
            &(*rootp)->right;                /* T4: follow right branch */
    }

    q = (addr_node*)ndpi_malloc(sizeof(addr_node));        /* T5: key not found */
    if (q != (addr_node*)0) {                        /* make new node */
        *rootp = q;                                        /* link new node to old */

        q->addr = key;
        q->version = version;
        strncpy(q->proto, proto, sizeof(q->proto) - 1);
        q->proto[sizeof(q->proto) - 1] = '\0';
        q->count = UPDATED_TREE;
        q->left = q->right = (addr_node*)0;

        return q->count;
    }

    return(0);
}

void ip_update_top(u_int32_t addr, u_int8_t version, const char* proto,
    int count, struct info_pair top[], int size) {
    struct info_pair pair;
    int min = count;
    int update = 0;
    int min_i = 0;
    int i;

    if (count == 0) return;

    pair.addr = addr;
    pair.version = version;
    pair.count = count;
    strncpy(pair.proto, proto, sizeof(pair.proto) - 1);
    pair.proto[sizeof(pair.proto) - 1] = '\0';

    for (i = 0; i < size; i++) {
      /* if the same ip with a bigger
         count just update it     */
        if (top[i].addr == addr) {
            top[i].count = count;
            return;
        }
        /* if array is not full yet
           add it to the first empty place */
        if (top[i].count == 0) {
            top[i] = pair;
            return;
        }
    }

    /* if bigger than the smallest one, replace it */
    for (i = 0; i < size; i++) {
        if (top[i].count < count && top[i].count < min) {
            min = top[i].count;
            min_i = i;
            update = 1;
        }
    }

    if (update)
        top[min_i] = pair;
}

/* *********************************************** */

/**
 * @brief Info pair
 */
int info_pair_cmp(const void* _a, const void* _b)
{
    struct info_pair* a = (struct info_pair*)_a;
    struct info_pair* b = (struct info_pair*)_b;

    return b->count - a->count;
}
