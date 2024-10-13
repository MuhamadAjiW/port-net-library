#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../include/lib-zmq.h"
#include "../../include/lib-string.h"

int lzmq_do_loop = 1;

/* ZeroMQ code */
uint8_t lzmq_send_to_server(char* ip, int port, FILE* file) {
    string_t address = str_format("tcp://%s:%d", ip, port);

    if (str_is_null(address)) {
        printf("Failed to allocate address string\n");
        return 1;
    }
    printf("ZMQ running at %s\n", address.content);

    void* context = zmq_ctx_new();

    void* socket = zmq_socket(context, ZMQ_PUB);
    int rc = zmq_bind(socket, address.content);
    if (rc != 0) {
        fprintf(stderr, "Failed to bind to ZeroMQ socket: %s\n", zmq_strerror(errno));
        str_delete(&address);
        return 2;
    }

    if (file == NULL) {
        fprintf(stderr, "Error: Unable to open CSV file.\n");
        str_delete(&address);
        return 3;
    }

    if (file) {
        fprintf(stderr, "Sending CSV file via ZeroMQ line by line\n");

        char* line = NULL;
        size_t len = 0;

        while (1) {
            int read = getline(&line, &len, file);

            if (read == -1) {
                if (feof(file)) {
                    fprintf(stderr, "End of file reached.\n");
                }
                else if (ferror(file)) {
                    perror("Error reading the file");
                }
                else {
                    fprintf(stderr, "Unknown error occured while reading the file.\n");
                }
                break;
            }

            fprintf(stderr, "Read line: %s", line);

            int send_rc = zmq_send(socket, line, strlen(line), 0);
            if (send_rc == -1) {
                fprintf(stderr, "Failed to send message via ZeroMQ: %s\n", zmq_strerror(errno));
                break;
            }

            fprintf(stderr, "Sent line: %s\n", line);

            memset(line, 0, len);
        }

        free(line);

        fprintf(stderr, "CSV file sending complete\n");
    }
    else {
        fprintf(stderr, "File pointer is NULL, cannot proceed.\n");
    }

    zmq_close(socket);
    zmq_ctx_destroy(context);

    str_delete(&address);

    return 0;
}

void* lzmq_do_nothing(__attribute__((unused)) void* arg) {
    while (lzmq_do_loop) {
        // printf("[DEV] Doing nothing with counter %d...\n", lzmq_do_loop);
        zmq_sleep(1);
    }
    // printf("\n[DEV] ZeroMQ done doing nothing\n");

    return 0;
}