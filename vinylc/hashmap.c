#include "hashmap.h"
#include <stdlib.h>
#include <memory.h>
#include <stdio.h>
#include <math.h>

KEY_HASH_FUNCTION(fnv1a_key_hash_str) {
    unsigned long long basis = 14695981039346656037ULL; // to be honest. i don't know what this is, thank u Google Bard
    unsigned long long prime = 1099511628211ULL;
    const char* ch = *(const char**)pKey;
    while (*(ch++) != '\0') {
        basis = (basis * prime) ^ (unsigned long long)ch;
    }
    return basis;
}

KEY_COMPARE_FUNCTION(key_compare_strcmp) {
    return strcmp(*(const char**)pKeyA, *(const char**)pKeyB) == 0;
}

struct ll_node create_ll_node() {
    struct ll_node out = {};
    return out;
}

struct ll_node* new_ll_node() {
    struct ll_node* llnode = (struct ll_node*)malloc(sizeof(struct ll_node));
    if (llnode == 0) return llnode;
    *llnode = create_ll_node();
    return llnode;
}

struct hashmap create_hashmap(unsigned int uNumBuckets, KEY_HASH_FUNCTION((*fpHashFunction)), KEY_COMPARE_FUNCTION((*fpCompareFunction))){
    struct hashmap out = {};
    out.uNumBuckets = uNumBuckets;  
    out.fpHashFunction = fpHashFunction;
    out.fpCompareFunction = fpCompareFunction;
    return out;
}

struct hashmap* new_hashmap(unsigned int uNumBuckets, KEY_HASH_FUNCTION((*fpHashFunction)), KEY_COMPARE_FUNCTION((*fpCompareFunction))) {
    struct hashmap* hashmap = (struct hashmap*)malloc(sizeof(struct hashmap));
    *hashmap = create_hashmap(uNumBuckets, fpHashFunction, fpCompareFunction);
    return hashmap;
}

unsigned long long get_bucket_idx(KEY_HASH_FUNCTION((*fpHashFunction)), void* pKey, unsigned int uNumBuckets) {
    return fpHashFunction(pKey) % uNumBuckets;
}

char hashmap_assert_not_initialized(struct hashmap* hSelf) {
    return hSelf->pBuckets == 0 ? HASHMAP_SUCCESS : HASHMAP_FAIL;
}

char init_hashmap(struct hashmap* hSelf, unsigned int uKeySz, unsigned int uValueSz) {
    if (hashmap_assert_not_initialized(hSelf) != HASHMAP_SUCCESS) return HASHMAP_ALREADY_INITIALIZED;
    unsigned int sz = hSelf->uNumBuckets * sizeof(struct ll_node*);
    hSelf->pBuckets = (struct ll_node**)malloc(sz);
    if (hSelf->pBuckets == 0) return HASHMAP_FAIL;
    memset(hSelf->pBuckets, 0, sz);
    hSelf->uKeySz = uKeySz;
    hSelf->uValueSz = uValueSz;
    return HASHMAP_SUCCESS;
}

char hashmap_get_bucket(struct hashmap* hSelf, void* pKey, struct ll_node** out_llnBucket) {
    if (hashmap_assert_not_initialized(hSelf) != HASHMAP_FAIL) return HASHMAP_NOT_INITIALIZED;
    unsigned long long bucketIdx = get_bucket_idx(hSelf->fpHashFunction, pKey, hSelf->uNumBuckets);
    *out_llnBucket = hSelf->pBuckets[bucketIdx];
    return HASHMAP_SUCCESS;
}

char hashmap_get_or_create_bucket(struct hashmap* hSelf, void* pKey, struct ll_node** out_llnBucket, char* out_bAlreadyExists) {
    char eBucket = hashmap_get_bucket(hSelf, pKey, out_llnBucket);
    if (eBucket != HASHMAP_SUCCESS) return eBucket;
    unsigned long long bucketIdx = get_bucket_idx(hSelf->fpHashFunction, pKey, hSelf->uNumBuckets);
    if (out_bAlreadyExists != 0) *out_bAlreadyExists = *out_llnBucket != 0;
    if (*out_llnBucket == 0) {
        *out_llnBucket = hSelf->pBuckets[bucketIdx] = new_ll_node();
    }
    if (*out_llnBucket == 0) return HASHMAP_FAIL;
    return HASHMAP_SUCCESS;
}

char hashmap_get_or_create_ll_node(struct hashmap* hSelf, void* pKey, struct ll_node** out_llnBucket, char* out_bAlreadyExists) {
    if (hashmap_assert_not_initialized(hSelf) != HASHMAP_FAIL) return HASHMAP_NOT_INITIALIZED;
    struct ll_node* bucket = 0;
    char eGetBucket = hashmap_get_or_create_bucket(hSelf, pKey, &bucket, out_bAlreadyExists);
    if (eGetBucket != HASHMAP_SUCCESS) return eGetBucket;
    if (!*out_bAlreadyExists) {
        *out_llnBucket = bucket;
    }
    if (*out_llnBucket == 0) {
        struct ll_node* last_bucket = bucket;
        while (bucket != 0) {
            if (hSelf->fpCompareFunction(bucket->pKey, pKey)) {
                *out_llnBucket = bucket;
                return HASHMAP_SUCCESS;
            }
            last_bucket = bucket;
            bucket = bucket->llnNext;
        }
        *out_llnBucket = last_bucket->llnNext = new_ll_node();
        if (*out_llnBucket == 0) return HASHMAP_FAIL;
    }
    (*out_llnBucket)->pKey = malloc(sizeof(hSelf->uKeySz));
    if ((*out_llnBucket)->pKey == 0) return HASHMAP_FAIL;
    memcpy((*out_llnBucket)->pKey, pKey, hSelf->uKeySz);
    *out_bAlreadyExists = 0;
    return HASHMAP_SUCCESS;
}

char hashmap_insert(struct hashmap* hSelf, void* pKey, void* pValue) {
    if (hashmap_assert_not_initialized(hSelf) != HASHMAP_FAIL) return HASHMAP_NOT_INITIALIZED;
    struct ll_node* bucket = 0;
    char alreadyExists;
    char eGetNode = hashmap_get_or_create_ll_node(hSelf, pKey, &bucket, &alreadyExists);
    if (eGetNode != HASHMAP_SUCCESS) return eGetNode;
    if (alreadyExists) return HASHMAP_KEY_ALREADY_EXISTS;
    bucket->pData = malloc(hSelf->uValueSz);
    memcpy(bucket->pData, pValue, hSelf->uValueSz);
    return HASHMAP_SUCCESS;
}

char hashmap_upsert(struct hashmap* hSelf, void* pKey, void* pValue) {
    if (hashmap_assert_not_initialized(hSelf) != HASHMAP_FAIL) return HASHMAP_NOT_INITIALIZED;
    struct ll_node* bucket = 0;
    char alreadyExists;
    char eGetNode = hashmap_get_or_create_ll_node(hSelf, pKey, &bucket, &alreadyExists);
    if (eGetNode != HASHMAP_SUCCESS) return eGetNode;
    if (bucket->pData != 0) free(bucket->pData);
    bucket->pData = malloc(hSelf->uValueSz);
    memcpy(bucket->pData, pValue, hSelf->uValueSz);
    return HASHMAP_SUCCESS;
}

char hashmap_delete(struct hashmap* hSelf, void* pKey) {
    if (hashmap_assert_not_initialized(hSelf) != HASHMAP_FAIL) return HASHMAP_NOT_INITIALIZED;
    unsigned long long bucketIdx = get_bucket_idx(hSelf->fpHashFunction, pKey, hSelf->uNumBuckets);
    struct ll_node* bucket = hSelf->pBuckets[bucketIdx];
    if (bucket == 0) return HASHMAP_KEY_DOES_NOT_EXIST;
    struct ll_node** thisPtr = &hSelf->pBuckets[bucketIdx];
    while (bucket != 0) {
        if (hSelf->fpCompareFunction(bucket->pKey, pKey)) {
            *thisPtr = bucket->llnNext;
            if (bucket->pData != 0) free(bucket->pData);
            free(bucket);
            return HASHMAP_SUCCESS;
        }
        thisPtr = &bucket->llnNext;
        bucket = bucket->llnNext;
    }
    return HASHMAP_KEY_DOES_NOT_EXIST;
}

char hashmap_has_key(struct hashmap* hSelf, void* pKey, char* out_bHasKey) {
    if (hashmap_assert_not_initialized(hSelf) != HASHMAP_FAIL) return HASHMAP_NOT_INITIALIZED;
    struct ll_node* bucket = 0;
    char eGetBucket = hashmap_get_bucket(hSelf, pKey, &bucket);
    if (eGetBucket != HASHMAP_SUCCESS) return eGetBucket;
    while (bucket != 0) {
        if (hSelf->fpCompareFunction(bucket->pKey, pKey)) {
            *out_bHasKey = 1;
            return HASHMAP_SUCCESS;
        }
        bucket = bucket->llnNext;
    }
    *out_bHasKey = 0;
    return HASHMAP_SUCCESS;
}

char hashmap_get_value(struct hashmap* hSelf, void* pKey, void* out_pValue) {
    void* valueRef = 0;
    char eGetRef = hashmap_get_value_ref(hSelf, pKey, &valueRef);
    if (eGetRef != HASHMAP_SUCCESS) return eGetRef;
    memcpy(out_pValue, valueRef, hSelf->uValueSz);
    return HASHMAP_SUCCESS;
}

char hashmap_get_value_ref(struct hashmap* hSelf, void* pKey, void** out_ppValue) {
    if (hashmap_assert_not_initialized(hSelf) != HASHMAP_FAIL) return HASHMAP_NOT_INITIALIZED;
    struct ll_node* bucket = 0;
    char eGetBucket = hashmap_get_bucket(hSelf, pKey, &bucket);
    if (eGetBucket != HASHMAP_SUCCESS) return eGetBucket;
    if (bucket == 0) return HASHMAP_KEY_DOES_NOT_EXIST;
    while (bucket != 0) {
        if (hSelf->fpCompareFunction(bucket->pKey, pKey)) {
            *out_ppValue = bucket->pData;
            return HASHMAP_SUCCESS;
        }
        bucket = bucket->llnNext;
    }
    return HASHMAP_KEY_DOES_NOT_EXIST;
}

char deinit_hashmap(struct hashmap* hSelf) {
    if (hashmap_assert_not_initialized(hSelf) != HASHMAP_FAIL) return HASHMAP_NOT_INITIALIZED;
    for (int i = 0; i < hSelf->uNumBuckets; i++) {
        struct ll_node* bucket = hSelf->pBuckets[i];
        while (bucket != 0) {
            if (bucket->pKey != 0) free(bucket->pKey);
            if (bucket->pData != 0) free(bucket->pData);
            struct ll_node* tmp = bucket;
            bucket = bucket->llnNext;
            free(tmp);
        }
    }
}

const char* generate_random_string(unsigned int len) {
    char* str = (char*)malloc(len);
    str[len] = '\0';
    for (int i = 0; i < len; i++) {
        str[i] = 65 + (rand() % 26);
    }
    return (const char*)str;
}