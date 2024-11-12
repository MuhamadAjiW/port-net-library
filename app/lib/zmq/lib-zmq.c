#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../include/lib-zmq.h"
#include "../../include/lib-string.h"

int lzmq_do_loop = 1;

int lzmq_int_init(struct lzmq_interface* lzmq_int, char* addr_cp, int type) {
    string_t address = str_format("tcp://%s", addr_cp);

    if (str_is_null(address)) {
        printf("Failed to allocate address string\n");
        return 0;
    }

    lzmq_int->context = zmq_ctx_new();
    lzmq_int->socket = zmq_socket(lzmq_int->context, type);

    int rc = 0;
    switch (type) {
    case ZMQ_PUB:
        rc = zmq_bind(lzmq_int->socket, address.content);
        break;
    case ZMQ_SUB:
        rc = zmq_connect(lzmq_int->socket, address.content);
        break;

    default:
        fprintf(stderr, "Invalid zeromq interface type: %s\n", zmq_strerror(errno));
        str_delete(&address);
        lzmq_int_cleanup(lzmq_int);
        return 0;
    }

    if (rc != 0) {
        fprintf(stderr, "Failed to bind to ZeroMQ socket: %s\n", zmq_strerror(errno));
        str_delete(&address);
        lzmq_int_cleanup(lzmq_int);
        return 0;
    }

    str_delete(&address);

    return 1;
}

uint8_t lzmq_int_initialized(struct lzmq_interface* interface) {
    return (interface->socket != 0) && (interface->context != 0);
}

void lzmq_int_cleanup(struct lzmq_interface* interface) {
    if (interface->socket != 0) {
        zmq_close(interface->socket);
    }
    if (interface->context != 0) {
        zmq_ctx_destroy(interface->context);
    }
}

uint8_t lzmq_send_file(struct lzmq_interface* interface, FILE* file, int flags) {
    if (!lzmq_int_initialized(interface)) return 0;

    if (file == NULL) {
        fprintf(stderr, "Error: Unable to open file.\n");
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

            int send_rc = zmq_send(interface->socket, line, strlen(line), flags);
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

    return 0;
}

uint8_t lzmq_send_str(struct lzmq_interface* interface, const char* data, int flags) {
    if (!lzmq_int_initialized(interface)) return 0;

    pthread_mutex_lock(&interface->mutex);
    zmq_send(interface->socket, data, strlen(data), flags);
    pthread_mutex_unlock(&interface->mutex);
    return 1;
}

uint8_t lzmq_send_json(struct lzmq_interface* interface, json_object* json, int flags) {
    if (!lzmq_int_initialized(interface)) return 0;

    const char* json_serialized = json_object_to_json_string(json);
    return lzmq_send_str(interface, json_serialized, flags);
}
