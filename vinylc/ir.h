#include "ast.h"

#ifndef IR_H
#define IR_H

#define IR_SUCCESS (char)0
#define IR_FAIL (char)1
#define IR_WRONG_NODE (char)2

void generate_intermediate_repr_var_decl(struct ast_elem* aeVarDecl);
void generate_intermediate_repr_stmt_list(struct ast_elem* aeRootElem);

#endif // IR_H  