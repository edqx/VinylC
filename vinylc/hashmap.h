#ifndef HASHMAP_H
#define HASHMAP_H

#define HASHMAP_SUCCESS (char)0
#define HASHMAP_FAIL (char)1
#define HASHMAP_NOT_INITIALIZED (char)2
#define HASHMAP_ALREADY_INITIALIZED (char)3
#define HASHMAP_KEY_ALREADY_EXISTS (char)4
#define HASHMAP_KEY_DOES_NOT_EXIST (char)5

#define KEY_HASH_FUNCTION(NAME) unsigned long long NAME(void* pKey)
#define KEY_COMPARE_FUNCTION(NAME) char NAME(void* pKeyA, void* pKeyB)

KEY_HASH_FUNCTION(fnv1a_key_hash_str);
KEY_COMPARE_FUNCTION(key_compare_strcmp);

struct ll_node {
    struct ll_node* llnNext;
    void* pKey;
    void* pData;
};

struct ll_node create_ll_node();
struct ll_node* new_ll_node();

struct hashmap {
    KEY_HASH_FUNCTION((*fpHashFunction));
    KEY_COMPARE_FUNCTION((*fpCompareFunction));
    unsigned int uNumBuckets;
    unsigned int uKeySz;
    unsigned int uValueSz;
    struct ll_node** pBuckets;
};

struct hashmap create_hashmap(unsigned int uNumBuckets, KEY_HASH_FUNCTION((*fpHashFunction)), KEY_COMPARE_FUNCTION((*fpCompareFunction)));
struct hashmap* new_hashmap(unsigned int uNumBuckets, KEY_HASH_FUNCTION((*fpHashFunction)), KEY_COMPARE_FUNCTION((*fpCompareFunction)));
unsigned long long get_bucket_idx(KEY_HASH_FUNCTION((*fpHashFunction)), void* pKey, unsigned int uNumBuckets);
char hashmap_assert_not_initialized(struct hashmap* hSelf);
char init_hashmap(struct hashmap* hSelf, unsigned int uKeySz, unsigned int uValueSz);
char hashmap_get_bucket(struct hashmap* hSelf, void* pKey, struct ll_node** out_llnBucket);
char hashmap_get_or_create_bucket(struct hashmap* hSelf, void* pKey, struct ll_node** out_llnBucket, char* out_bAlreadyExists);
char hashmap_get_or_create_ll_node(struct hashmap* hSelf, void* pKey, struct ll_node** out_llnBucket, char* out_bAlreadyExists);
char hashmap_insert(struct hashmap* hSelf, void* pKey, void* pValue);
char hashmap_upsert(struct hashmap* hSelf, void* pKey, void* pValue);
char hashmap_delete(struct hashmap* hSelf, void* pKey);
char hashmap_has_key(struct hashmap* hSelf, void* pKey, char* out_bHasKey);
char hashmap_get_value(struct hashmap* hSelf, void* pKey, void* out_pValue);
char hashmap_get_value_ref(struct hashmap* hSelf, void* pKey, void** out_ppValue);
char deinit_hashmap(struct hashmap* hSelf);

#endif // HASHMAP_H