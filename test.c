#include "vector.h"
#include "lexer.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    FILE* file = fopen(argv[1], "r");
    fseek(file, 0, SEEK_END); 
    int size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* fileBuffer = (char*)malloc(size + 1);
    fread(fileBuffer, 1, size, file);
    fileBuffer[size] = '\0';

    char ret = get_tokens("hello.vinyl", fileBuffer);

    return 0;
}