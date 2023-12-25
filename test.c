#include "vector.h"
#include "lexer.h"
#include <stdio.h>

int main(int argc, char** argv) {
    struct vector someVec = create_vector();
    init_vector(&someVec, 4, sizeof(int));

    int a = 5;
    vector_append(&someVec, &a);
    vector_append(&someVec, &a);
    int b = 6;
    vector_append(&someVec, &b);

    int out1, out2, out3;
    vector_pop(&someVec, &out1);
    vector_pop(&someVec, &out2);
    vector_pop(&someVec, &out3);

    const char* myProgram = "532534.432 234";
    get_tokens("hello.vinyl", myProgram);

    return 0;
}