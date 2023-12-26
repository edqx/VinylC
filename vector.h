#ifndef VECTOR_H
#define VECTOR_H

#define VECTOR_SUCCESS (char)0
#define VECTOR_FAIL (char)1
#define VECTOR_ALREADY_INITIALIZED (char)2
#define VECTOR_NOT_INITIALIZED (char)3
#define VECTOR_OOB (char)4

struct vector {
    void* data;
    unsigned int uElementSz;
    unsigned int uLength;
    unsigned int uCapacity;
};

struct vector create_vector();
char vector_assert_not_initialized(struct vector* vSelf);
char init_vector(struct vector* vSelf, unsigned int uCapacity, unsigned int uElementSz);
char vector_expand(struct vector* vSelf, unsigned int uNewCapacity);
char vector_append(struct vector* vSelf, void* pElement);
char vector_pop(struct vector* vSelf, void* out_pElement);
char vector_at(struct vector* vSelf, unsigned int uIndex, void* out_pElement);
char vector_at_ref(struct vector* vSelf, unsigned int uIndex, void** out_ppElement);
char deinit_vector(struct vector* vSelf);

#endif // VECTOR_H