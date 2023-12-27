#include "vector.h"
#include "lexer.h"
#include "ast.h"
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

    struct vector defectList = create_vector();
    init_vector(&defectList, 512, sizeof(struct lexer_defect));

    struct vector tokenList = create_vector();
    init_vector(&tokenList, 512, sizeof(struct token));

    char ret = get_tokens("hello.vinyl", fileBuffer, &defectList, &tokenList);

    struct token** tokens = malloc(tokenList.uLength * sizeof(struct token*));
    for (int i = 0; i < tokenList.uLength; i++) {
        vector_at_ref(&tokenList, i, (void**)&tokens[i]);
    }

    struct vector syntaxErrorList = create_vector();
    init_vector(&syntaxErrorList, 512, sizeof(struct syntax_error));

    struct ast_node* ast_node = 0;
    build_stmt_list_node(tokens, &syntaxErrorList, tokenList.uLength, &ast_node);

    for (int i = 0; i < syntaxErrorList.uLength; i++) {
        struct syntax_error err;
        vector_at(&syntaxErrorList, i, &err);
        print_error(fileBuffer, err);
    }

    print_ast_string((struct ast_elem*)ast_node, 0);

    return 0;
}