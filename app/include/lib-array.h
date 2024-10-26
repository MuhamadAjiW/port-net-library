#ifndef _LIB_ARRAY_H
#define _LIB_ARRAY_H

#include "stdint.h"
#include "stdlib.h"
#include "string.h"
#include "lib-base.h"

#define DYNARRAY_DEFAULT_SIZE 8

// TODO: Document
// Structs
typedef struct dynarray_t {
    void* content;
    uint64_t length;
    uint64_t max_size;
    uint64_t element_size;
} dynarray_t;

// Functions
void dynarray_init(dynarray_t* array, uint64_t element_size);
void dynarray_resize(dynarray_t* array, uint64_t new_max_size);
void dynarray_delete(dynarray_t* array);
void dynarray_push_back(dynarray_t* array, void* content);
void dynarray_pop_back(dynarray_t* array);

#endif