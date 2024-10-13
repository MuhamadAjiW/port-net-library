#include "../../include/lib-ndpi.h"

// _TODO: Break down further into smaller libs

/* *********************************************** */

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

/* *********************************************** */

/**
 * @brief Packets stats format
 */
char* formatPackets(float numPkts, char* buf) {

    if (numPkts < 1000) {
        ndpi_snprintf(buf, 32, "%.2f", numPkts);
    }
    else if (numPkts < (1000 * 1000)) {
        ndpi_snprintf(buf, 32, "%.2f K", numPkts / 1000);
    }
    else {
        numPkts /= (1000 * 1000);
        ndpi_snprintf(buf, 32, "%.2f M", numPkts);
    }

    return(buf);
}

/* *********************************************** */

/**
 * @brief Bytes stats format
 */
char* formatBytes(u_int32_t howMuch, char* buf, u_int buf_len) {
    char unit = 'B';

    if (howMuch < 1024) {
        ndpi_snprintf(buf, buf_len, "%lu %c", (unsigned long)howMuch, unit);
    }
    else if (howMuch < (1024 * 1024)) {
        ndpi_snprintf(buf, buf_len, "%.2f K%c", (float)(howMuch) / 1024, unit);
    }
    else {
        float tmpGB = ((float)howMuch) / (1024 * 1024);

        if (tmpGB < 1024) {
            ndpi_snprintf(buf, buf_len, "%.2f M%c", tmpGB, unit);
        }
        else {
            tmpGB /= 1024;

            ndpi_snprintf(buf, buf_len, "%.2f G%c", tmpGB, unit);
        }
    }

    return(buf);
}

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

/* *********************************************** */

/**
 * @brief Traffic stats format
 */
char* formatTraffic(float numBits, int bits, char* buf) {
    char unit;

    if (bits)
        unit = 'b';
    else
        unit = 'B';

    if (numBits < 1024) {
        ndpi_snprintf(buf, 32, "%lu %c", (unsigned long)numBits, unit);
    }
    else if (numBits < (1024 * 1024)) {
        ndpi_snprintf(buf, 32, "%.2f K%c", (float)(numBits) / 1024, unit);
    }
    else {
        float tmpMBits = ((float)numBits) / (1024 * 1024);

        if (tmpMBits < 1024) {
            ndpi_snprintf(buf, 32, "%.2f M%c", tmpMBits, unit);
        }
        else {
            tmpMBits /= 1024;

            if (tmpMBits < 1024) {
                ndpi_snprintf(buf, 32, "%.2f G%c", tmpMBits, unit);
            }
            else {
                ndpi_snprintf(buf, 32, "%.2f T%c", (float)(tmpMBits) / 1024, unit);
            }
        }
    }

    return(buf);
}