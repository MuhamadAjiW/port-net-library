#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../../include/lib-string.h"
#include "../../include/lib-base.h"

string_t str_new(char* initial) {
    string_t retval;

    int counter = 0;
    while (initial[counter] != 0) {
        counter++;
    }
    retval.content = malloc(counter + 1);
    if (retval.content == NULL) return NULL_STRING;

    for (int i = 0; i < counter; i++) {
        retval.content[i] = initial[i];
    }
    retval.content[counter] = 0;
    retval.len = counter;

    return retval;
}

string_t str_newcopy(string_t source) {
    string_t retval;

    retval.content = malloc(source.len + 1);
    if (retval.content == NULL) return NULL_STRING;

    for (uint32_t i = 0; i < source.len; i++) {
        retval.content[i] = source.content[i];
    }
    retval.content[source.len] = 0;
    retval.len = source.len;

    return retval;
}

void str_delete(string_t* string) {
    free(string->content);
}

bool str_is_null(string_t source) {
    return (source.len == NULL_STRING.len && source.content == NULL_STRING.content);
}

string_t str_splice_rear(string_t mainstring, uint32_t loc) {
    if (loc > mainstring.len) return NULL_STRING;

    string_t retval;
    retval.len = mainstring.len - loc;

    retval.content = malloc(retval.len + 1);
    if (retval.content == NULL) return NULL_STRING;

    for (uint32_t i = 0; i < retval.len; i++) {
        retval.content[i] = mainstring.content[loc + i];
    }
    retval.content[retval.len] = 0;
    return retval;
}

string_t str_splice_front(string_t mainstring, uint32_t loc) {
    string_t retval;
    retval.len = loc;

    retval.content = malloc(retval.len + 1);
    if (retval.content == NULL) return NULL_STRING;

    for (uint32_t i = 0; i < retval.len; i++) {
        retval.content[i] = mainstring.content[i];
    }
    retval.content[retval.len] = 0;
    return retval;
}

string_t int_to_string_t(int x) {
    string_t retval;

    retval.len = snprintf(NULL, 0, "%d", x) + 1;
    retval.content = malloc(sizeof(char) * retval.len);
    if (retval.content == NULL) return NULL_STRING;

    int_to_string(x, retval.content);

    return retval;
}

int int_parse_string_t(string_t str) {
    if (str_is_null(str)) return 0;
    return atoi(str.content);
}

bool str_concat(string_t* mainstring, string_t substring) {
    char* new_content = realloc(mainstring->content, mainstring->len + substring.len + 1);
    if (new_content == NULL) return false;
    mainstring->content = new_content;

    for (uint32_t i = 0; i < substring.len; i++) {
        mainstring->content[mainstring->len + i] = substring.content[i];
    }
    mainstring->len += substring.len;
    mainstring->content[mainstring->len] = 0;

    return true;
}

bool str_consdot(string_t* mainstring, string_t substring) {
    char* new_content = realloc(mainstring->content, mainstring->len + substring.len + 1);
    if (new_content == NULL) return false;

    string_t temp = str_newcopy(*mainstring);
    if (str_is_null(temp)) return false;

    mainstring->content = new_content;

    for (uint32_t i = 0; i < substring.len; i++) {
        mainstring->content[i] = substring.content[i];
    }
    for (uint32_t i = 0; i < mainstring->len; i++) {
        mainstring->content[substring.len + i] = temp.content[i];
    }
    str_delete(&temp);
    mainstring->len += substring.len;
    mainstring->content[mainstring->len] = 0;

    return true;
}

bool str_insertc(string_t* mainstring, char c, uint32_t loc) {
    if (loc > mainstring->len) return;

    char* new_content = realloc(mainstring->content, mainstring->len + 2);
    if (new_content == NULL) return false;

    mainstring->content = new_content;

    for (uint32_t i = mainstring->len; i > loc; i--) {
        mainstring->content[i] = mainstring->content[i - 1];
    }
    mainstring->content[loc] = c;
    mainstring->content[mainstring->len + 1] = 0;
    mainstring->len++;

    return true;
}

char str_remove(string_t* mainstring, uint32_t loc) {
    if (loc >= mainstring->len) return NULL_CHAR;

    char retval = mainstring->content[loc];

    for (uint32_t i = loc; i < mainstring->len; i++) {
        mainstring->content[i] = mainstring->content[i + 1];
    }
    mainstring->content[mainstring->len - 1] = 0;
    char* new_content = realloc(mainstring->content, mainstring->len);
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
    char* new_content = realloc(mainstring->content, mainstring->len + 2);
    if (new_content == NULL) return false;

    mainstring->content = new_content;
    mainstring->content[mainstring->len] = c;
    mainstring->content[mainstring->len + 1] = 0;
    mainstring->len++;

    return true;
}
