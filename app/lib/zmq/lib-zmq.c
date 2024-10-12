#include <stdio.h>
#include "../../include/lib-zmq.h"
#include "../../include/lib-string.h"

/* ZeroMQ code */
void send_to_server(char* ip, int port, FILE* file) {
    // char* str_address = NULL;
    // int str_address = snprintf(NULL, 0, "tcp://%s:%d", ip, port) + 1;

    void* context = zmq_ctx_new();


    // void* socket = zmq_socket(context, ZMQ_PUB);
    // int rc = zmq_bind(socket, "tcp://*:5556");
    // if (rc != 0) {
    //     fprintf(stderr, "Failed to bind to ZeroMQ socket: %s\n", zmq_strerror(errno));
    //     return -1;
    // }

    // if (file == NULL) {
    //     fprintf(stderr, "Error: Unable to open CSV file.\n");
    //     return -1;
    // }

    // if (results_file) {
    //     fprintf(stderr, "Sending CSV file via ZeroMQ line by line\n");

    //     char* line = NULL;
    //     size_t len = 0;

    //     while (1) {
    //         ssize_t read = getline(&line, &len, results_file);

    //         if (read == -1) {
    //             if (feof(results_file)) {
    //                 fprintf(stderr, "End of CSV file reached.\n");
    //             }
    //             else {
    //                 fprintf(stderr, "Error reading the CSV file.\n");
    //             }
    //             break;
    //         }

    //         fprintf(stderr, "Read line: %s", line);

    //         int send_rc = zmq_send(socket, line, strlen(line), 0);
    //         if (send_rc == -1) {
    //             fprintf(stderr, "Failed to send message via ZeroMQ: %s\n", zmq_strerror(errno));
    //             break;
    //         }

    //         fprintf(stderr, "Sent line: %s\n", line);

    //         //clear line buffer
    //         memset(line, 0, len);
    //     }

    //     zmq_close(socket);
    //     zmq_ctx_destroy(context);
    //     fclose(results_file);
    //     free(line);

    //     fprintf(stderr, "CSV file sending complete\n");
    // }
    // else {
    //     fprintf(stderr, "File pointer is NULL, cannot proceed.\n");
    // }

    // zmq_close(socket);
    zmq_ctx_destroy(context);
}