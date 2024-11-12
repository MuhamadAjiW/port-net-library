#include "../../include/lib-array.h"

void dynarray_init(dynarray_t* array, uint64_t element_size) {
    array->content = ndpi_malloc(element_size * DYNARRAY_DEFAULT_SIZE);
    array->length = 0;
    array->element_size = element_size;
    array->max_size = DYNARRAY_DEFAULT_SIZE;
}

void dynarray_resize(dynarray_t* array, uint64_t new_max_size) {
    array->content = ndpi_realloc(
        array->content,
        array->max_size * array->element_size,
        new_max_size * array->element_size
    );
    array->max_size = new_max_size;
}

void dynarray_delete(dynarray_t* array) {
    if (array->content != NULL) {
        ndpi_free(array->content);
        array->content = NULL;
        array->length = 0;
        array->max_size = 0;
    }
}

void dynarray_push_back(dynarray_t* array, void* content) {
    if (array->length == array->max_size) {
        dynarray_resize(array, array->max_size * 2);
    }

    memcpy(array->content + (array->length * array->element_size), content, array->element_size);
    array->length++;
}

void dynarray_pop_back(dynarray_t* array) {
    if (array->length > 0) {
        array->length--;
    }
}
