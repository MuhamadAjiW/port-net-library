#include <zmq.h>
#include <json-c/json.h>
#include "../include/lib-string.h"

uint8_t lzmq_send_to_server(char* ip, int port) {
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
        zmq_close(socket);
        zmq_ctx_destroy(context);
        return 2;
    }

    json_object* json = json_object_new_object();
    string_t message = str_new("Hello!");

    json_object_object_add(json, "message", json_object_new_string(message.content));

    for (size_t i = 0; i < 50; i++) {
        const char* json_serialized = json_object_to_json_string(json);
        zmq_send(socket, json_serialized, strlen(json_serialized), 0);
        printf("Sent message: %s\n", message.content);

        zmq_sleep(1);
    }

    zmq_close(socket);
    zmq_ctx_destroy(context);

    str_delete(&address);
    json_object_put(json);

    return 0;
}


int main() {
    char* ip = "127.0.0.1";
    int port = 8888;

    uint8_t retcode = lzmq_send_to_server(ip, port);

    printf("\nProgram finished with return code %u\n", retcode);
    return 0;
}