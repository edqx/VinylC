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

    struct vector defect_list = create_vector();
    init_vector(&defect_list, 512, sizeof(struct lexer_defect));

    struct vector token_list = create_vector();
    init_vector(&token_list, 512, sizeof(struct token));

    char ret = get_tokens("hello.vinyl", fileBuffer, &defect_list, &token_list);

    struct token** tokens = malloc(token_list.uLength * sizeof(struct token*));
    for (int i = 0; i < token_list.uLength; i++) {
        vector_at_ref(&token_list, i, (void**)&tokens[i]);
    }

    struct ast_node* ast_node = 0;
    build_stmt_list_node(tokens, token_list.uLength, &ast_node);

    print_ast_string((struct ast_elem*)ast_node, 0);

    return 0;
}