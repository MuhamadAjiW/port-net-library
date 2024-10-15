#include "../../include/lib-flow.h"

int cmpFlows(const void* _a, const void* _b) {
    struct ndpi_flow_info* fa = ((struct flow_info*)_a)->flow;
    struct ndpi_flow_info* fb = ((struct flow_info*)_b)->flow;
    uint64_t a_size = fa->src2dst_bytes + fa->dst2src_bytes;
    uint64_t b_size = fb->src2dst_bytes + fb->dst2src_bytes;
    if (a_size != b_size)
        return a_size < b_size ? 1 : -1;

      // copy from ndpi_workflow_node_cmp();

    if (fa->ip_version < fb->ip_version) return(-1); else { if (fa->ip_version > fb->ip_version) return(1); }
    if (fa->protocol < fb->protocol) return(-1); else { if (fa->protocol > fb->protocol) return(1); }
    if (htonl(fa->src_ip) < htonl(fb->src_ip)) return(-1); else { if (htonl(fa->src_ip) > htonl(fb->src_ip)) return(1); }
    if (htons(fa->src_port) < htons(fb->src_port)) return(-1); else { if (htons(fa->src_port) > htons(fb->src_port)) return(1); }
    if (htonl(fa->dst_ip) < htonl(fb->dst_ip)) return(-1); else { if (htonl(fa->dst_ip) > htonl(fb->dst_ip)) return(1); }
    if (htons(fa->dst_port) < htons(fb->dst_port)) return(-1); else { if (htons(fa->dst_port) > htons(fb->dst_port)) return(1); }
    if (fa->vlan_id < fb->vlan_id) return(-1); else { if (fa->vlan_id > fb->vlan_id) return(1); }
    return(0);
}