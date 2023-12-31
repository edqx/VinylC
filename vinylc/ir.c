#include "ir.h"

void generate_intermediate_repr_var_decl(struct ast_elem* aeVarDecl) {
    if (aeVarDecl->iKind != AST_NODE_KIND_VAR_DECL_STMT) return IR_WRONG_NODE;
}

void generate_intermediate_repr_stmt_list(struct ast_elem* aeRootElem) {
    if (aeRootElem->iKind != AST_NODE_KIND_STMT_LIST) return IR_WRONG_NODE;

    struct ast_node* rootNode = (struct ast_node*)aeRootElem;
    for (int i = 0; i < rootNode->uNumElements; i++) {
        struct ast_elem* subNode = (struct node*)rootNode->ppElements[i];
    }
}