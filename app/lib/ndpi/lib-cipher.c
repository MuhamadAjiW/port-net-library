#include "../../include/lib-cipher.h"

char* is_unsafe_cipher(ndpi_cipher_weakness c) {
    switch (c) {
    case ndpi_cipher_insecure:
        return("INSECURE");
        break;

    case ndpi_cipher_weak:
        return("WEAK");
        break;

    default:
        return("OK");
    }
}

/* *********************************************** */

/*function to use in HASH_SORT function in verbose == 4 to order in creasing order to delete host with the leatest occurency*/
int hash_stats_sort_to_order(void* _a, void* _b) {
    struct hash_stats* a = (struct hash_stats*)_a;
    struct hash_stats* b = (struct hash_stats*)_b;

    return (a->occurency - b->occurency);
}

/* *********************************************** */

/*function to use in HASH_SORT function in verbose == 4 to print in decreasing order*/
int hash_stats_sort_to_print(void* _a, void* _b) {
    struct hash_stats* a = (struct hash_stats*)_a;
    struct hash_stats* b = (struct hash_stats*)_b;

    return (b->occurency - a->occurency);
}