#define VECTOR_SUCCESS '\0'
#define VECTOR_FAIL '\1'
#define VECTOR_ALREADY_INITIALIZED '\2'
#define VECTOR_NOT_INITIALIZED '\3'
#define VECTOR_OOB '\4'

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
char deinit_vector(struct vector* vSelf);