#include "../../include/lib-string.h"

string_t str_new(char* initial) {
    string_t retval;

    retval.len = strlen(initial);
    retval.content = ndpi_malloc(retval.len + 1);
    if (retval.content == NULL) return NULL_STRING;

    memcpy(retval.content, initial, retval.len);
    retval.content[retval.len] = NULL_CHAR;

    return retval;
}

string_t str_newcopy(string_t source) {
    string_t retval;

    retval.content = ndpi_malloc(source.len + 1);
    if (retval.content == NULL) return NULL_STRING;

    memcpy(retval.content, source.content, source.len);
    retval.content[source.len] = NULL_CHAR;
    retval.len = source.len;

    return retval;
}

void str_delete(string_t* string) {
    ndpi_free(string->content);
}

bool str_is_null(string_t source) {
    return (source.len == NULL_STRING.len && source.content == NULL_STRING.content);
}

string_t str_splice_rear(string_t mainstring, uint32_t loc) {
    if (loc > mainstring.len) return NULL_STRING;

    string_t retval;
    retval.len = mainstring.len - loc;

    retval.content = ndpi_malloc(retval.len + 1);
    if (retval.content == NULL) return NULL_STRING;

    memcpy(retval.content, mainstring.content + loc, retval.len);
    retval.content[retval.len] = NULL_CHAR;

    return retval;
}

string_t str_splice_front(string_t mainstring, uint32_t loc) {
    string_t retval;
    retval.len = loc;

    retval.content = ndpi_malloc(retval.len + 1);
    if (retval.content == NULL) return NULL_STRING;

    memcpy(retval.content, mainstring.content, retval.len);
    retval.content[retval.len] = NULL_CHAR;
    return retval;
}

string_t int_to_string_t(int x) {
    string_t retval;

    retval.len = snprintf(NULL, 0, "%d", x) + 1;
    retval.content = ndpi_malloc(sizeof(char) * retval.len);
    if (retval.content == NULL) return NULL_STRING;
    snprintf(retval.content, retval.len, "%d", x);

    return retval;
}

int int_parse_string_t(string_t str) {
    if (str_is_null(str)) return 0;
    return atoi(str.content);
}

bool str_concat(string_t* mainstring, string_t substring) {
    char* new_content = ndpi_realloc(mainstring->content, mainstring->len + 1, mainstring->len + substring.len + 1);
    if (new_content == NULL) return false;
    mainstring->content = new_content;

    memcpy(mainstring->content + mainstring->len, substring.content, substring.len);
    mainstring->len += substring.len;
    mainstring->content[mainstring->len] = NULL_CHAR;

    return true;
}

bool str_consdot(string_t* mainstring, string_t substring) {
    char* new_content = ndpi_realloc(mainstring->content, mainstring->len + 1, mainstring->len + substring.len + 1);
    if (new_content == NULL) return false;

    mainstring->content = new_content;

    memmove(mainstring->content + substring.len, mainstring->content, mainstring->len + 1);
    memcpy(mainstring->content, substring.content, substring.len);

    mainstring->len += substring.len;
    mainstring->content[mainstring->len] = NULL_CHAR;

    return true;
}

bool str_insertc(string_t* mainstring, char c, uint32_t loc) {
    if (loc > mainstring->len) return false;

    char* new_content = ndpi_realloc(mainstring->content, mainstring->len + 1, mainstring->len + 2);
    if (new_content == NULL) return false;

    mainstring->content = new_content;

    memmove(mainstring->content + loc + 1, mainstring->content + loc, mainstring->len - loc);
    mainstring->content[loc] = c;
    mainstring->content[mainstring->len + 1] = NULL_CHAR;
    mainstring->len++;

    return true;
}

char str_remove(string_t* mainstring, uint32_t loc) {
    if (loc >= mainstring->len) return NULL_CHAR;

    char retval = mainstring->content[loc];

    memmove(mainstring->content + loc, mainstring->content + loc + 1, mainstring->len - loc - 1);
    mainstring->content[mainstring->len - 1] = NULL_CHAR;
    char* new_content = ndpi_realloc(mainstring->content, mainstring->len + 1, mainstring->len);
    mainstring->len--;

    if (new_content == NULL) return retval;
    mainstring->content = new_content;

    return retval;
}

bool str_add(string_t* mainstring, char* substring) {
    string_t temp = str_new(substring);
    if (str_is_null(temp)) return false;

    str_concat(mainstring, temp);
    str_delete(&temp);

    return true;
}

bool str_addc(string_t* mainstring, char c) {
    char* new_content = ndpi_realloc(mainstring->content, mainstring->len + 1, mainstring->len + 2);
    if (new_content == NULL) return false;

    mainstring->content = new_content;
    mainstring->content[mainstring->len] = c;
    mainstring->content[mainstring->len + 1] = NULL_CHAR;
    mainstring->len++;

    return true;
}

string_t str_format(char* __restrict__ pattern, ...) {
    string_t retval;

    va_list args;
    va_start(args, pattern);
    retval.len = vsnprintf(NULL, 0, pattern, args) + 1;
    va_end(args);

    retval.content = ndpi_malloc(retval.len);
    if (retval.content == NULL) return NULL_STRING;

    va_start(args, pattern);
    vsnprintf(retval.content, retval.len, pattern, args);
    va_end(args);

    return retval;
}

/* ***************************************************** */

uint8_t parse_ip_port(char* address, char* ip, int* port) {
    char* port_mark = strrchr(address, ':');

    if (!port_mark) return 0;

    strncpy(ip, address, port_mark - address);
    ip[port_mark - address] = '\0';
    *port = atoi(port_mark + 1);

    return 1;
}