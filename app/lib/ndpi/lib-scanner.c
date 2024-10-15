#include "../../include/lib-scanner.h"

/* *********************************************** */

void deleteScanners(struct single_flow_info* scanners) {
    struct single_flow_info* s, * tmp;
    struct port_flow_info* p, * tmp2;

    HASH_ITER(hh, scanners, s, tmp) {
        HASH_ITER(hh, s->ports, p, tmp2) {
            if (s->ports) HASH_DEL(s->ports, p);
            ndpi_free(p);
        }
        HASH_DEL(scanners, s);
        ndpi_free(s);
    }
}

/* *********************************************** */

void updateScanners(struct single_flow_info** scanners, u_int32_t saddr,
    u_int8_t version, u_int32_t dport) {
    struct single_flow_info* f;
    struct port_flow_info* p;

    HASH_FIND_INT(*scanners, (int*)&saddr, f);

    if (f == NULL) {
        f = (struct single_flow_info*)ndpi_malloc(sizeof(struct single_flow_info));
        if (!f) return;
        f->saddr = saddr;
        f->version = version;
        f->tot_flows = 1;
        f->ports = NULL;

        p = (struct port_flow_info*)ndpi_malloc(sizeof(struct port_flow_info));

        if (!p) {
            ndpi_free(f);
            return;
        }
        else
            p->port = dport, p->num_flows = 1;

        HASH_ADD_INT(f->ports, port, p);
        HASH_ADD_INT(*scanners, saddr, f);
    }
    else {
        struct port_flow_info* pp;
        f->tot_flows++;

        HASH_FIND_INT(f->ports, (int*)&dport, pp);

        if (pp == NULL) {
            pp = (struct port_flow_info*)ndpi_malloc(sizeof(struct port_flow_info));
            if (!pp) return;
            pp->port = dport, pp->num_flows = 1;

            HASH_ADD_INT(f->ports, port, pp);
        }
        else
            pp->num_flows++;
    }
}