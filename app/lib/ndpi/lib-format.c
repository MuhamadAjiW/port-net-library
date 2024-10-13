#include "../../include/lib-format.h"

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
