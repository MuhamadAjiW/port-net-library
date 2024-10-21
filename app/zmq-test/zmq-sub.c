#include <zmq.h>
#include <time.h>
#include <json-c/json.h>
#include "../include/lib-string.h"

uint8_t lzmq_receive_from_server(char* ip, int port, FILE* output_file) {
    string_t address = str_format("tcp://%s:%d", ip, port);

    if (str_is_null(address)) {
        printf("Failed to allocate address string\n");
        return 1;
    }
    printf("Subscribed to ZMQ running at %s\n", address.content);

    void* context = zmq_ctx_new();
    void* socket = zmq_socket(context, ZMQ_SUB);
    int rc = zmq_connect(socket, address.content);

    if (rc != 0) {
        fprintf(stderr, "Failed to connect to ZeroMQ: %s\n", zmq_strerror(errno));
        str_delete(&address);
        zmq_close(socket);
        zmq_ctx_destroy(context);
        return 2;
    }

    if (output_file == NULL) {
        fprintf(stderr, "Error: Invalid output file.\n");
        str_delete(&address);
        zmq_close(socket);
        zmq_ctx_destroy(context);
        return 3;
    }

    zmq_setsockopt(socket, ZMQ_SUBSCRIBE, "", 0);

    char buffer[512];
    char timestamp[20];
    time_t time_now;
    struct tm* t;
    while (1) {
        printf("\nPolling...\n");
        int bytes_received = zmq_recv(socket, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received > 0) {
            time_now = time(NULL);
            t = localtime(&time_now);
            strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

            buffer[bytes_received] = 0;
            printf("Received data: %s\n", buffer);

            fprintf(output_file, "%s: %s\n", timestamp, buffer);
            fflush(output_file);
        }
    }

    zmq_close(socket);
    zmq_ctx_destroy(context);

    str_delete(&address);

    return 0;
}

int main() {
    char* ip = "127.0.0.1";
    int port = 8888;
    FILE* output_file = fopen("out.ignore", "w+");
    if (output_file == NULL) {
        perror("Error: Failed opening output file");
    }

    uint8_t retcode = lzmq_receive_from_server(ip, port, output_file);
    fclose(output_file);

    printf("\nProgram finished with return code %u\n", retcode);
    return 0;
}