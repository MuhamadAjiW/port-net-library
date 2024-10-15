#include "../../include/lib-receiver.h"
#include "../../include/reader_util.h"
#include "../../include/uthash.h"

/* *********************************************** */

void receivers_delete(struct receiver* rcvrs) {
    struct receiver* current, * tmp;

    HASH_ITER(hh, rcvrs, current, tmp) {
        HASH_DEL(rcvrs, current);
        ndpi_free(current);
    }
}

/* *********************************************** */
/* implementation of: https://jeroen.massar.ch/presentations/files/FloCon2010-TopK.pdf
 *
 * if(table1.size < max1 || receivers_acceptable) {
 *    create new element and add to the table1
 *    if(table1.size > max2) {
 *      cut table1 back to max1
 *      merge table 1 to table2
 *      if(table2.size > max1)
 *        cut table2 back to max1
 *    }
 * }
 * else
 *   update table1
 */
void receivers_update(struct receiver** rcvrs, u_int32_t dst_addr,
    u_int8_t version, u_int32_t num_pkts,
    struct receiver** topRcvrs) {
    struct receiver* r;
    u_int32_t size;
    int a;

    HASH_FIND_INT(*rcvrs, (int*)&dst_addr, r);
    if (r == NULL) {
        if (((size = HASH_COUNT(*rcvrs)) < MAX_TABLE_SIZE_1)
            || ((a = receivers_acceptable(num_pkts)) != 0)) {
            r = (struct receiver*)ndpi_malloc(sizeof(struct receiver));
            if (!r) return;

            r->addr = dst_addr;
            r->version = version;
            r->num_pkts = num_pkts;

            HASH_ADD_INT(*rcvrs, addr, r);

            if ((size = HASH_COUNT(*rcvrs)) > MAX_TABLE_SIZE_2) {

                HASH_SORT(*rcvrs, receivers_sort_asc);
                *rcvrs = receivers_cut_back_to(rcvrs, size, MAX_TABLE_SIZE_1);
                receivers_merge_tables(rcvrs, topRcvrs);

                if ((size = HASH_COUNT(*topRcvrs)) > MAX_TABLE_SIZE_1) {
                    HASH_SORT(*topRcvrs, receivers_sort_asc);
                    *topRcvrs = receivers_cut_back_to(topRcvrs, size, MAX_TABLE_SIZE_1);
                }

                *rcvrs = NULL;
            }
        }
    }
    else
        r->num_pkts += num_pkts;
}

/* *********************************************** */

int receivers_sort_asc(void* _a, void* _b) {
    struct receiver* a = (struct receiver*)_a;
    struct receiver* b = (struct receiver*)_b;

    return(a->num_pkts - b->num_pkts);
}

/* ***************************************************** */
/*@brief removes first (size - max) elements from hash table.
 * hash table is ordered in ascending order.
 */
struct receiver* receivers_cut_back_to(struct receiver** rcvrs, u_int32_t size, u_int32_t max) {
    struct receiver* r, * tmp;
    int i = 0;
    int count;

    if (size < max) //return the original table
        return *rcvrs;

    count = size - max;

    HASH_ITER(hh, *rcvrs, r, tmp) {
        if (i++ == count)
            return r;
        HASH_DEL(*rcvrs, r);
        ndpi_free(r);
    }

    return(NULL);

}

/* *********************************************** */

/* @brief heuristic choice for receiver stats */
int receivers_acceptable(u_int32_t num_pkts) {
    return num_pkts > 5;
}

/* *********************************************** */
/*@brief merge first table to the second table.
 * if element already in the second table
 *  then updates its value
 * else adds it to the second table
 */
void receivers_merge_tables(struct receiver** primary, struct receiver** secondary) {
    struct receiver* r, * s, * tmp;

    HASH_ITER(hh, *primary, r, tmp) {
        HASH_FIND_INT(*secondary, (int*)&(r->addr), s);
        if (s == NULL) {
            s = (struct receiver*)ndpi_malloc(sizeof(struct receiver));
            if (!s) return;

            s->addr = r->addr;
            s->version = r->version;
            s->num_pkts = r->num_pkts;

            HASH_ADD_INT(*secondary, addr, s);
        }
        else
            s->num_pkts += r->num_pkts;

        HASH_DEL(*primary, r);
        ndpi_free(r);
    }
}
