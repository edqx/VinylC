#include "vector.h"
#include <memory.h>
#include <stdlib.h>

struct vector create_vector() {
    struct vector out = {};
    return out;
}

struct vector* new_vector() {
    struct vector* vec = (struct vector*)malloc(sizeof(struct vector));
    *vec = create_vector();
    return vec;
}

char vector_assert_not_initialized(struct vector* vSelf) {
    if (vSelf->data == 0) return VECTOR_SUCCESS;
    return VECTOR_FAIL;
}

char init_vector(struct vector* vSelf, unsigned int uCapacity, unsigned int uElementSz) {
    void* data = malloc(uCapacity * uElementSz);
    if (data == 0) return VECTOR_FAIL;

    vSelf->data = data;
    vSelf->uElementSz = uElementSz;
    vSelf->uLength = 0;
    vSelf->uCapacity = uCapacity;
    return VECTOR_SUCCESS;
}

char vector_expand(struct vector* vSelf, unsigned int uNewCapacity) {
    if(vector_assert_not_initialized(vSelf) == VECTOR_SUCCESS) return VECTOR_NOT_INITIALIZED;

    void* newData = realloc(vSelf->data, uNewCapacity * vSelf->uElementSz);
    if (newData == 0) return VECTOR_FAIL;
    vSelf->uCapacity = uNewCapacity;
    vSelf->data = newData;
    return VECTOR_SUCCESS;
}

char vector_append(struct vector* vSelf, void* pElement) {
    if(vector_assert_not_initialized(vSelf) == VECTOR_SUCCESS) return VECTOR_NOT_INITIALIZED;

    if (vSelf->uLength >= vSelf->uCapacity)
        if (vector_expand(vSelf, vSelf->uLength == 0 ? 1 : vSelf->uLength * 2) == VECTOR_FAIL) return VECTOR_FAIL;

    memcpy(vSelf->data + (vSelf->uLength * vSelf->uElementSz), pElement, vSelf->uElementSz);
    vSelf->uLength++;
    return VECTOR_SUCCESS;
}

char vector_append_concat(struct vector* vSelf, struct vector* vOther) {
    if(vector_assert_not_initialized(vSelf) == VECTOR_SUCCESS) return VECTOR_NOT_INITIALIZED;
    if(vector_assert_not_initialized(vOther) == VECTOR_SUCCESS) return VECTOR_NOT_INITIALIZED;
    if (vSelf->uElementSz != vOther->uElementSz) return VECTOR_DIFFERENT_SIZE;
    if (vOther->uLength == 0) return VECTOR_SUCCESS;

    if (vSelf->uLength + vOther->uLength > vSelf->uCapacity)
        if (vector_expand(vSelf, vSelf->uLength + vOther->uLength) == VECTOR_FAIL) return VECTOR_FAIL;

    memcpy(vSelf->data + (vSelf->uLength * vSelf->uElementSz), vOther->data, vOther->uElementSz * vOther->uLength);
    vSelf->uLength += vOther->uLength;
    return VECTOR_SUCCESS;
}

char vector_clear(struct vector* vSelf) {
    if(vector_assert_not_initialized(vSelf) == VECTOR_SUCCESS) return VECTOR_NOT_INITIALIZED;
    vSelf->uLength = 0;
    return VECTOR_SUCCESS;
}

char vector_pop(struct vector* vSelf, void* out_pElement) {
    if(vector_assert_not_initialized(vSelf) == VECTOR_SUCCESS) return VECTOR_NOT_INITIALIZED;
    if (vSelf->uLength <= 0) return VECTOR_OOB;

    vSelf->uLength--;
    if (out_pElement != 0) memcpy(out_pElement, vSelf->data + (vSelf->uLength * vSelf->uElementSz), vSelf->uElementSz);
    return VECTOR_SUCCESS;
}

char vector_shift(struct vector* vSelf, void* out_pElement) {
    if(vector_assert_not_initialized(vSelf) == VECTOR_SUCCESS) return VECTOR_NOT_INITIALIZED;
    if (vSelf->uLength <= 0) return VECTOR_OOB;
    if (out_pElement != 0) memcpy(out_pElement, vSelf->data, vSelf->uElementSz);
    void* newBuf = malloc(vSelf->uCapacity * vSelf->uElementSz);
    if (newBuf == 0) return VECTOR_FAIL;
    vSelf->uLength--;
    memcpy(newBuf, vSelf->data + vSelf->uElementSz, vSelf->uLength * vSelf->uElementSz);
    free(vSelf->data);
    vSelf->data = newBuf;
    return VECTOR_SUCCESS;
}

char vector_unshift(struct vector* vSelf, void* pElement) {
    if(vector_assert_not_initialized(vSelf) == VECTOR_SUCCESS) return VECTOR_NOT_INITIALIZED;
    int newCapacity = vSelf->uLength >= vSelf->uCapacity ? (vSelf->uLength == 0 ? 1 : vSelf->uLength * 2) : vSelf->uCapacity;
    void* newBuf = malloc(vSelf->uCapacity * vSelf->uElementSz);
    if (newBuf == 0) return VECTOR_FAIL;
    memcpy(newBuf + vSelf->uElementSz, vSelf->data, vSelf->uLength * vSelf->uElementSz);
    memcpy(newBuf, pElement, vSelf->uElementSz);
    free(vSelf->data);
    vSelf->data = newBuf;
    vSelf->uLength++;
    return VECTOR_SUCCESS;
}

char vector_at(struct vector* vSelf, unsigned int uIndex, void* out_pElement) {
    if(vector_assert_not_initialized(vSelf) == VECTOR_SUCCESS) return VECTOR_NOT_INITIALIZED;
    if (uIndex >= vSelf->uLength) return VECTOR_OOB;

    memcpy(out_pElement, vSelf->data + (uIndex * vSelf->uElementSz), vSelf->uElementSz);
    return VECTOR_SUCCESS;
}

char vector_at_ref(struct vector* vSelf, unsigned int uIndex, void** out_ppElement) {
    if(vector_assert_not_initialized(vSelf) == VECTOR_SUCCESS) return VECTOR_NOT_INITIALIZED;
    if (uIndex >= vSelf->uLength) return VECTOR_OOB;

    *out_ppElement = vSelf->data + (uIndex * vSelf->uElementSz);
    return VECTOR_SUCCESS;
}

char deinit_vector(struct vector* vSelf) {
    if (vector_assert_not_initialized(vSelf) == VECTOR_SUCCESS) return VECTOR_NOT_INITIALIZED;

    free(vSelf->data);
    vSelf->data = 0;
    return VECTOR_SUCCESS;
}