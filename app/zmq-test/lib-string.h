#ifndef _LIB_STRING_H
#define _LIB_STRING_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include "../include/lib-base.h"

#define NULL_STRING (string_t){ NULL, 0 }

/**
 * Struct of string
 *
 * @param content   string contents
 * @param len       length of the string
*/
typedef struct string_t {
    char* content;
    uint32_t len;
} string_t;

/**
 * String struct constructor
 *
 * @param initial   string contents
 * @return          a new string struct
 *
 * @warning         returns NULL_STRING if allocation fails
*/
string_t str_new(char* initial);

/**
 * String struct copy constructor
 *
 * @param source    string to copy from
 * @return          a new string struct
 *
 * @warning         returns NULL_STRING if allocation fails
*/
string_t str_newcopy(string_t source);

/**
 * Deallocates string content
 *
 * @param string    string to delete
*/
void str_delete(string_t* string);

/**
 * String struct copy constructor
 *
 * @param source    string to check
 * @return          1 if true, 0 if false
*/
bool str_is_null(string_t source);

/**
 * Creates a new substring from a string from a point to the front
 *
 * @param mainstring    string to splice
 * @param loc           location of splice
 * @return              spliced string, NULL_STRING if loc > mainstring.len
 *
 * @warning             does not deallocate mainstring, returns NULL_STRING if allocation fails
*/
string_t str_splice_rear(string_t mainstring, uint32_t loc);

/**
 * Creates a new substring from a string from a point to the rear
 *
 * @param mainstring    string to splice
 * @param loc           location of splice
 * @return              spliced string, NULL_STRING if loc > mainstring.len
 *
 * @warning             does not deallocate mainstring, returns NULL_STRING if allocation fails
*/
string_t str_splice_front(string_t mainstring, uint32_t loc);

/**
 * Convert an integer to a string struct
 *
 * @param x             integer
 * @return              a new string struct
 *
 * @warning             returns NULL_STRING if allocation fails
*/
string_t int_to_string_t(int x);

/**
 * Convert an integer to a string struct
 *
 * @param x             integer
 * @return              an int value of str or 0 if str is invalid
*/
int int_parse_string_t(string_t str);

/**
 * Joins two string at the end
 *
 * @param mainstring    string to concat to
 * @param substring     string to concat from
 * @return              true if successful, false if allocation fails
 *
 * @warning             does not deallocate substring
*/
bool str_concat(string_t* mainstring, string_t substring);

/**
 * Joins two string at the start
 *
 * @param mainstring    string to concat to
 * @param substring     string to concat from
 * @return              true if successful, false if allocation fails
 *
 * @warning             does not deallocate substring
*/
bool str_consdot(string_t* mainstring, string_t substring);

/**
 * Inserts a char at a location
 *
 * @param mainstring    string to add to
 * @param c             char to be added
 * @param loc           index of char after addition
 * @return              true if successful, false if allocation fails
 *
 * @warning             mainstring will not change if loc is bigger than mainstring.len
*/
bool str_insertc(string_t* mainstring, char c, uint32_t loc);

/**
 * Removes a char at a location
 *
 * @param mainstring    string to add to
 * @param loc           index of char to be removed
 * @return              removed char, NULL_CHAR if invalid
 *
 * @warning             mainstring will not change if loc is bigger or equal than mainstring.len
*/
char str_remove(string_t* mainstring, uint32_t loc);

/**
 * Extends a string with another much like concat
 *
 * @param mainstring    string to add to
 * @param substring     string to be added
 * @return              true if successful, false if allocation fails
*/
bool str_add(string_t* mainstring, char* substring);

/**
 * Extends a string with a single char
 *
 * @param mainstring    string to add to
 * @param c             char to be added
 * @return              true if successful, false if allocation fails
*/
bool str_addc(string_t* mainstring, char c);

/**
 * Takes a formatted char array to be a string struct
 *
 * @param pattern       string pattern
 * @param args          arguments to be added
 * @return              string struct with formatted content
 *
 * @warning             returns NULL_STRING if allocation fails
*/
string_t str_format(char* __restrict__ pattern, ...);

/* ***************************************************** */

uint8_t parse_ip_port(char* address, char* ip, int* port);

#endif